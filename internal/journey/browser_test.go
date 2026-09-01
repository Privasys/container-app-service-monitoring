// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package journey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/visual"
)

// A browser journey is judged here, not in the renderer, so these tests
// are about the judging: what a screenshot has to show for the page to
// count as up, and what happens to a credential on the way across.

// stubRenderer stands in for the attested browser. It records what it
// was asked to do, which is how the credential tests read what actually
// crossed the gap.
type stubRenderer struct {
	server   *httptest.Server
	received map[string]any
	body     []byte
	reply    map[string]any
}

func newStubRenderer(t *testing.T, reply map[string]any) *stubRenderer {
	t.Helper()
	s := &stubRenderer{reply: reply}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		s.body = body.Bytes()
		_ = json.Unmarshal(s.body, &s.received)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.reply)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *stubRenderer) client() *journey.BrowserClient {
	return &journey.BrowserClient{URL: s.server.URL, Token: "test-token", Insecure: true}
}

// screenshot renders a synthetic page: bars of dark on white, or
// nothing at all.
func screenshot(bars int) string {
	img := image.NewRGBA(image.Rect(0, 0, 320, 200))
	for y := 0; y < 200; y++ {
		for x := 0; x < 320; x++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	for i := 0; i < bars; i++ {
		for y := 20 + i*18; y < 34+i*18 && y < 200; y++ {
			for x := 20; x < 300; x++ {
				img.Set(x, y, color.RGBA{20, 20, 20, 255})
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func hashOf(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	a, err := visual.Analyse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a.Hash
}

func browserMonitor(steps []model.Step) *model.Monitor {
	return &model.Monitor{
		Name: "checkout", Engine: model.EngineBrowser,
		IntervalSeconds: 60, TimeoutSeconds: 30,
		FailureThreshold: 1, RecoveryThreshold: 1,
		Steps: steps,
	}
}

func TestABrowserJourneyReadsThePage(t *testing.T) {
	shot := screenshot(6)
	stub := newStubRenderer(t, map[string]any{
		"ok": true, "duration_ms": 900,
		"steps": []map[string]any{
			{"name": "open", "kind": "goto", "ok": true},
			{"name": "read", "kind": "text", "ok": true,
				"text": "Order accepted\nTotal: 42.00 GBP", "screenshot": shot},
		},
	})

	engine := journey.New(newVault(t, "app.example.com"), openList())
	engine.Browser = stub.client()

	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto, URL: "https://app.example.com/checkout"},
		{
			Name: "read", Kind: model.StepReadPage, Capture: true,
			Screenshot: &model.ScreenshotCheck{},
			Assertions: []model.Assertion{
				{Source: model.SrcBody, Op: model.OpContains, Value: "Total: 42.00 GBP"},
			},
		},
	})

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictUp {
		t.Fatalf("verdict = %s (%s): %s", res.Verdict, res.FailedStep, res.Detail)
	}
	if len(res.Captures) != 1 {
		t.Fatalf("captures = %d, want 1", len(res.Captures))
	}
	c := res.Captures[0]
	if c.Digest == "" || c.Hash == "" || c.Width != 320 || c.Height != 200 {
		t.Fatalf("capture = %+v", c)
	}
	if c.InkPPM == 0 {
		t.Fatal("a page with content measured as empty")
	}
}

// The check that earns the screenshot: a page that answers, renders
// nothing, and would pass every assertion about its own text because it
// has none.
func TestABlankPageIsDownEvenWhenTheJourneySucceeds(t *testing.T) {
	stub := newStubRenderer(t, map[string]any{
		"ok": true, "duration_ms": 400,
		"steps": []map[string]any{
			{"name": "open", "kind": "goto", "ok": true},
			{"name": "look", "kind": "screenshot", "ok": true, "screenshot": screenshot(0)},
		},
	})

	engine := journey.New(newVault(t, "app.example.com"), openList())
	engine.Browser = stub.client()

	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto, URL: "https://app.example.com/"},
		{Name: "look", Kind: model.StepScreenshot, Screenshot: &model.ScreenshotCheck{}},
	})

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictDown {
		t.Fatalf("verdict = %s, want down: %s", res.Verdict, res.Detail)
	}
	if !strings.Contains(res.Detail, "rendered almost nothing") {
		t.Fatalf("detail = %q", res.Detail)
	}
	// A failure keeps the picture, because that is when somebody wants
	// to look at it.
	if len(res.Captures) != 1 || !res.Captures[0].Stored {
		t.Fatalf("a failing capture was not kept: %+v", res.Captures)
	}
}

func TestAPageThatChangedFailsItsBaseline(t *testing.T) {
	approved := screenshot(6)
	changed := screenshot(2)

	stub := newStubRenderer(t, map[string]any{
		"ok": true, "duration_ms": 500,
		"steps": []map[string]any{
			{"name": "open", "kind": "goto", "ok": true},
			{"name": "look", "kind": "screenshot", "ok": true, "screenshot": changed},
		},
	})
	engine := journey.New(newVault(t, "app.example.com"), openList())
	engine.Browser = stub.client()

	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto, URL: "https://app.example.com/"},
		{Name: "look", Kind: model.StepScreenshot, Screenshot: &model.ScreenshotCheck{
			Baseline: hashOf(t, approved), MaxDistance: 8,
		}},
	})

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictDown {
		t.Fatalf("verdict = %s, want down", res.Verdict)
	}
	if !strings.Contains(res.Detail, "no longer looks like the approved baseline") {
		t.Fatalf("detail = %q", res.Detail)
	}

	// The same page against its own baseline passes, and says how far it
	// was rather than only that it was near enough.
	stub.reply["steps"] = []map[string]any{
		{"name": "open", "kind": "goto", "ok": true},
		{"name": "look", "kind": "screenshot", "ok": true, "screenshot": approved},
	}
	res = engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictUp {
		t.Fatalf("verdict = %s, want up: %s", res.Verdict, res.Detail)
	}
	if res.Captures[0].Distance != 0 {
		t.Fatalf("distance from its own baseline = %d, want 0", res.Captures[0].Distance)
	}
}

// The credential reaches the renderer, because that is the point of
// pinning its measurement, and it does not come back in anything the
// record would keep.
func TestTheCredentialCrossesOnceAndComesBackRedacted(t *testing.T) {
	stub := newStubRenderer(t, map[string]any{
		"ok": true, "duration_ms": 700,
		"steps": []map[string]any{
			{"name": "open", "kind": "goto", "ok": true},
			{"name": "password", "kind": "fill", "ok": true},
			// A page that reflects what it was given, which is how a
			// credential ends up in a monitoring vendor's database.
			{"name": "read", "kind": "text", "ok": true,
				"text": "Signed in as s3cr3t-value-not-in-the-record"},
		},
	})

	engine := journey.New(newVault(t, "app.example.com"), openList())
	engine.Browser = stub.client()

	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto, URL: "https://app.example.com/login"},
		{Name: "password", Kind: model.StepFill, Selector: "#password",
			Value: "{{ secrets.api_key }}"},
		{Name: "read", Kind: model.StepReadPage, Capture: true},
	})

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictUp {
		t.Fatalf("verdict = %s: %s", res.Verdict, res.Detail)
	}
	if !bytes.Contains(stub.body, []byte("s3cr3t-value-not-in-the-record")) {
		t.Fatal("the credential did not reach the renderer")
	}
	for _, step := range res.Steps {
		if strings.Contains(step.Capture, "s3cr3t-value-not-in-the-record") {
			t.Fatalf("the credential came back into the record: %q", step.Capture)
		}
	}
}

// The binding still holds across the gap: a credential bound to one
// host is not typed into a page served by another.
func TestACredentialIsNotTypedIntoAnotherHostsPage(t *testing.T) {
	stub := newStubRenderer(t, map[string]any{"ok": true})
	engine := journey.New(newVault(t, "app.example.com"), openList())
	engine.Browser = stub.client()

	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto, URL: "https://attacker.test/login"},
		{Name: "password", Kind: model.StepFill, Selector: "#password",
			Value: "{{ secrets.api_key }}"},
	})

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictError || res.ErrorClass != model.ErrClassPolicy {
		t.Fatalf("verdict = %s / %s, want error / policy", res.Verdict, res.ErrorClass)
	}
	if !strings.Contains(res.Detail, "not bound to that host") {
		t.Fatalf("detail = %q", res.Detail)
	}
	if stub.body != nil {
		t.Fatal("a request reached the renderer despite the refusal")
	}
}

// A renderer running a build nobody pinned is our failure, not the
// watched service's, so it costs coverage rather than availability.
func TestAnUnreachableRendererIsAnErrorNotAnOutage(t *testing.T) {
	engine := journey.New(newVault(t, "app.example.com"), openList())
	engine.Browser = &journey.BrowserClient{
		URL: "http://127.0.0.1:1", Token: "t", Insecure: true,
	}
	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto, URL: "https://app.example.com/"},
	})
	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictError {
		t.Fatalf("verdict = %s, want error", res.Verdict)
	}

	// And a monitor that needs a browser when none is configured says so
	// rather than quietly measuring nothing.
	engine.Browser = nil
	res = engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictError ||
		!strings.Contains(res.Detail, "no renderer has been configured") {
		t.Fatalf("verdict = %s, detail = %q", res.Verdict, res.Detail)
	}
}

// What the renderer reports about the page is downtime; what it reports
// about itself is not.
func TestTheRenderersFailureIsClassifiedByWhoseItIs(t *testing.T) {
	for _, tc := range []struct {
		class string
		want  string
	}{
		{"selector", model.VerdictDown},
		{"navigation", model.VerdictDown},
		{"timeout", model.VerdictDown},
		{"internal", model.VerdictError},
	} {
		stub := newStubRenderer(t, map[string]any{
			"ok": false, "error_class": tc.class, "failed_step": "wait",
			"error": "something went wrong", "duration_ms": 100,
			"steps": []map[string]any{{"name": "open", "kind": "goto", "ok": true}},
		})
		engine := journey.New(newVault(t, "app.example.com"), openList())
		engine.Browser = stub.client()

		res := engine.Run(context.Background(), browserMonitor([]model.Step{
			{Name: "open", Kind: model.StepGoto, URL: "https://app.example.com/"},
		}))
		if res.Verdict != tc.want {
			t.Fatalf("a %s failure gave %s, want %s", tc.class, res.Verdict, tc.want)
		}
	}
}

// A journey definition that puts a credential in a URL is refused
// before it runs, in the browser vocabulary as well as the HTTP one.
func TestABrowserJourneyMayNotPutACredentialInAURL(t *testing.T) {
	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto,
			URL: "https://app.example.com/?token={{ secrets.api_key }}"},
	})
	if err := mon.Validate(); err == nil {
		t.Fatal("a credential in a URL was accepted")
	}
}

func TestABrowserJourneyNeedsANavigation(t *testing.T) {
	mon := browserMonitor([]model.Step{
		{Name: "click", Kind: model.StepClick, Selector: "#go"},
	})
	if err := mon.Validate(); err == nil {
		t.Fatal("a journey that never navigates was accepted")
	}
}

// A page that logged nothing must satisfy an assertion that it logged
// nothing. Getting this backwards makes the check useless in the one
// direction anybody writes it.
func TestAQuietConsoleSatisfiesAnAbsenceAssertion(t *testing.T) {
	stub := newStubRenderer(t, map[string]any{
		"ok": true, "duration_ms": 300,
		"steps": []map[string]any{
			{"name": "open", "kind": "goto", "ok": true},
			{"name": "read", "kind": "text", "ok": true, "text": "all well"},
		},
	})
	engine := journey.New(newVault(t, "app.example.com"), openList())
	engine.Browser = stub.client()

	mon := browserMonitor([]model.Step{
		{Name: "open", Kind: model.StepGoto, URL: "https://app.example.com/"},
		{Name: "read", Kind: model.StepReadPage, Capture: true,
			Assertions: []model.Assertion{
				{Source: model.SrcConsole, Op: model.OpAbsent,
					Message: "the page reported an error to its own console"},
			}},
	})

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictUp {
		t.Fatalf("a quiet console failed an absence assertion: %s", res.Detail)
	}

	// And a page that did log an error fails it.
	stub.reply["console"] = []string{"error: Uncaught TypeError"}
	res = engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictDown {
		t.Fatalf("a console error was not noticed: verdict = %s", res.Verdict)
	}
	if !strings.Contains(res.Detail, "reported an error") {
		t.Fatalf("detail = %q", res.Detail)
	}
}
