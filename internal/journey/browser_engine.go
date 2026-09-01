// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package journey

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/visual"
)

// runBrowser executes a journey through the renderer and decides what
// it means here.
//
// The split is the point. The renderer says what the page did; this
// decides whether that counts as available, because this is the process
// that has to produce a report somebody can recompute. Every judgement
// below is arithmetic over what came back: a status, a distance between
// two hashes, a proportion of non-background pixels. Nothing here asks
// an opinion of anything.
func (e *Engine) runBrowser(ctx context.Context, m *model.Monitor) Result {
	start := e.now()
	red := secrets.NewRedactor()
	used := map[string]bool{}
	res := Result{Verdict: model.VerdictUp, Vars: map[string]string{}}

	if !e.Browser.Configured() {
		res.Verdict = model.VerdictError
		res.ErrorClass = model.ErrClassPolicy
		res.Detail = "this monitor runs in a browser, and no renderer has been configured"
		return res
	}

	body, fail := buildBrowserRequest(m, e.Secrets, red, used)
	if fail != nil {
		res.Verdict = verdictFor(fail.class)
		res.ErrorClass = fail.class
		res.Detail = red.Redact(fail.detail)
		res.DurationMs = int(e.now().Sub(start) / time.Millisecond)
		return res
	}
	res.UsedSecrets = names(used)

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = model.DefaultTimeout * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	rendered, err := e.Browser.Render(runCtx, body)
	if err != nil {
		// The renderer being unreachable, or running a build nobody
		// pinned, is our failure and not the watched service's. It costs
		// coverage; it is never downtime.
		res.Verdict = model.VerdictError
		res.ErrorClass = model.ErrClassPolicy
		res.Detail = red.Redact(err.Error())
		res.DurationMs = int(e.now().Sub(start) / time.Millisecond)
		return res
	}

	byName := map[string]*model.Step{}
	for i := range m.Steps {
		byName[m.Steps[i].Name] = &m.Steps[i]
	}

	pageText, ocrText := "", ""
	for _, rs := range rendered.Steps {
		sr := model.StepResult{
			Name: rs.Name, Kind: rs.Kind, OK: rs.OK,
			DurationMs: rs.DurationMs, Detail: red.Redact(rs.Detail),
		}
		if rs.Text != "" {
			pageText = rs.Text
			sr.Capture = red.Redact(capture(rs.Text))
		}
		if rs.OCRText != "" {
			ocrText = rs.OCRText
		}
		if rs.Value != "" {
			res.Vars[rs.Name] = rs.Value
		}

		// The screenshot is measured here and travels to the caller as
		// bytes plus numbers. The numbers go in the record; the bytes go
		// on the sealed volume if the check asked for them.
		if spec := screenshotSpec(byName[rs.Name]); spec != nil && rs.Screenshot != "" {
			capture, reason := e.measure(rs.Name, rs.Screenshot, spec)
			if capture != nil {
				res.Captures = append(res.Captures, *capture)
				sr.Detail = strings.TrimSpace(sr.Detail + " " + capture.Summary())
			}
			if reason != "" {
				sr.OK = false
				res.Verdict = model.VerdictDown
				res.FailedStep = rs.Name
				res.ErrorClass = model.ErrClassAssertion
				res.Detail = reason
			}
		}
		res.Steps = append(res.Steps, sr)
	}

	// A failure the renderer reported outranks anything measured here:
	// if the page never got to the state a screenshot was of, what the
	// screenshot shows is beside the point.
	if !rendered.OK {
		res.Verdict = verdictFor(browserClass(rendered.ErrorClass))
		res.ErrorClass = browserClass(rendered.ErrorClass)
		res.FailedStep = rendered.FailedStep
		res.Detail = red.Redact(rendered.Error)
	}

	// Assertions run over what the page said, in the same vocabulary as
	// an HTTP journey: the document's text is the body, and recognised
	// text and console output are sources of their own.
	if res.Verdict == model.VerdictUp {
		obs := &observation{
			body: pageText, vars: res.Vars, status: 200,
			latency: rendered.DurationMs,
			headers: map[string]string{},
		}
		obs.vars[VarOCRText] = ocrText
		obs.vars[VarConsole] = strings.Join(rendered.Console, "\n")
		for i := range m.Steps {
			if f := e.checks(&m.Steps[i], obs, res.Vars, m.Steps[i].Name); f != nil {
				res.Verdict = verdictFor(f.class)
				res.ErrorClass = f.class
				res.FailedStep = m.Steps[i].Name
				res.Detail = red.Redact(f.detail)
				break
			}
		}
	}

	res.DurationMs = int(e.now().Sub(start) / time.Millisecond)
	if res.Verdict == model.VerdictUp && m.LatencyBudgetMs > 0 && res.DurationMs > m.LatencyBudgetMs {
		res.Verdict = model.VerdictDegraded
		res.Detail = fmt.Sprintf("the journey completed in %dms, over the %dms budget",
			res.DurationMs, m.LatencyBudgetMs)
	}

	if leaked(red, &res) {
		res.Verdict = model.VerdictError
		res.ErrorClass = model.ErrClassRedaction
		res.Detail = "a credential appeared in the captured output; the capture was discarded"
		for i := range res.Steps {
			res.Steps[i].Capture = ""
			res.Steps[i].Detail = ""
		}
		res.Captures = nil
	}
	return res
}

// Variables the browser engine publishes so assertions can read what
// only a rendered page has.
const (
	VarOCRText = "__ocr_text"
	VarConsole = "__console"
)

// measure analyses one screenshot and decides whether it passes.
func (e *Engine) measure(step, encoded string, spec *model.ScreenshotCheck) (*model.Capture, string) {
	png, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "the renderer's screenshot did not decode"
	}
	masks := make([]visual.Region, 0, len(spec.Masks))
	for _, r := range spec.Masks {
		masks = append(masks, visual.Region{X: r.X, Y: r.Y, W: r.W, H: r.H})
	}
	analysis, err := visual.Analyse(png, masks)
	if err != nil {
		return nil, err.Error()
	}

	out := &model.Capture{
		Step: step, Digest: analysis.Digest, Hash: analysis.Hash,
		InkPPM: analysis.InkPPM, Width: analysis.Width, Height: analysis.Height,
		Bytes: analysis.Bytes, Distance: -1, PNG: png,
	}

	reason := ""
	// Did anything render at all? This is the check that catches a white
	// screen behind an HTTP 200, and it is worth more than every clever
	// one after it.
	if analysis.Blank(spec.MinInkPPM) {
		reason = fmt.Sprintf("the page rendered almost nothing: %s of it is not background",
			model.FormatInk(analysis.InkPPM))
	}

	if spec.Baseline != "" {
		distance, err := visual.Distance(spec.Baseline, analysis.Hash)
		if err != nil {
			return out, err.Error()
		}
		out.Distance = distance
		limit := spec.MaxDistance
		if limit == 0 {
			limit = visual.DefaultDistance
		}
		if distance > limit && reason == "" {
			reason = fmt.Sprintf(
				"the page no longer looks like the approved baseline: %d bits differ, the limit is %d",
				distance, limit)
		}
	}

	// Storing is a policy, not an afterthought. The digest is in the
	// record either way; the image is what a responder wants to look at,
	// so it is kept when something went wrong or when the page changed.
	switch spec.Store {
	case model.StoreAlways:
		out.Stored = true
	case model.StoreNever:
		out.PNG = nil
	default:
		out.Stored = reason != "" || (spec.Baseline != "" && out.Distance > 0)
	}
	if !out.Stored {
		out.PNG = nil
	}
	return out, reason
}

func screenshotSpec(s *model.Step) *model.ScreenshotCheck {
	if s == nil {
		return nil
	}
	return s.Screenshot
}

// browserClass maps the renderer's vocabulary onto ours. A selector that
// never appeared is the page failing to do what a customer needs, which
// is downtime; the renderer failing to run is not.
func browserClass(class string) string {
	switch class {
	case "navigation":
		return model.ErrClassConnect
	case "selector":
		return model.ErrClassAssertion
	case "timeout":
		return model.ErrClassTimeout
	case "script":
		return model.ErrClassAssertion
	default:
		return model.ErrClassPolicy
	}
}

func names(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	return out
}
