// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package model

import (
	"errors"
	"fmt"
	"strings"
)

// Browser journeys.
//
// The same monitor shape, driven through a real browser instead of an
// HTTP client, because some services are only exercised the way a
// customer exercises them: a form that runs on submit, a dashboard that
// assembles itself after the document loads, a checkout that is three
// scripts and a redirect. An HTTP journey proves the API answered. A
// browser journey proves the page worked.
//
// It costs more, so it is a choice rather than the default, and it runs
// in a separate enclave whose measurement the owner pins.

// Engines a monitor can run under.
const (
	EngineHTTP    = "http"
	EngineBrowser = "browser"
)

// Browser step kinds. They are the actions a person takes, and no more:
// a journey nobody can read is no use in the argument a report is
// written for.
const (
	StepGoto       = "goto"
	StepClick      = "click"
	StepFill       = "fill"
	StepPress      = "press"
	StepWaitFor    = "wait"
	StepScreenshot = "screenshot"
	StepReadPage   = "read"
	StepEval       = "eval"
)

// Viewport is the window a browser journey runs in, and part of what a
// screenshot means: the same page at another width is another picture.
type Viewport struct {
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`
	// OCR asks the renderer to recognise text in each screenshot as well
	// as returning the document's own text. It is for words a page draws
	// rather than writes: a canvas, a chart, an error baked into an
	// image. Everywhere else the document's text is exact and free.
	OCR bool `json:"ocr,omitempty"`
}

// Region is a rectangle excluded from a visual comparison: a clock, a
// carousel, a "last updated" line. A baseline without them is a
// baseline that fails every minute and teaches everyone to ignore it.
type Region struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

// ScreenshotCheck is what a capture is compared against.
//
// Both tests are arithmetic over pixels, and that is the point. A
// report's claim is that its numbers recompute from the evidence it
// carries; a model's opinion about whether a page looks right does not
// recompute, so it cannot be what decides an availability figure. A
// model is useful for explaining a difference to a person afterwards.
type ScreenshotCheck struct {
	// Baseline is the perceptual hash somebody approved, as 16 hex
	// characters. It lives on the monitor definition, so approving a new
	// one is a new monitor version: authored, timestamped, with a
	// message saying why the page is allowed to look different now.
	Baseline string `json:"baseline,omitempty"`
	// MaxDistance is how many bits of that hash may differ. Anti
	// aliasing and a changed number move a couple; a redesign, a blank
	// page or a consent wall move many more.
	MaxDistance int `json:"max_distance,omitempty"`
	// MinInkPPM is how much of the image must not be background for the
	// page to count as rendered at all. This is the check that catches
	// the white screen of death behind an HTTP 200.
	MinInkPPM int64 `json:"min_ink_ppm,omitempty"`
	// Masks are regions excluded from both measurements.
	Masks []Region `json:"masks,omitempty"`
	// Store keeps the image on the sealed volume. The digest is recorded
	// either way; the image itself is what a responder wants to look at,
	// and what a later dispute needs, so the default is to keep it on
	// failure and on change.
	Store string `json:"store,omitempty"`
}

// When a screenshot is kept.
const (
	StoreAlways  = "always"
	StoreOnFault = "on_fault"
	StoreNever   = "never"
)

// BrowserKind maps a step to the renderer's vocabulary.
func (s *Step) BrowserKind() string {
	switch s.Kind {
	case StepGoto, StepClick, StepFill, StepPress, StepEval:
		return s.Kind
	case StepWaitFor:
		return "wait"
	case StepSleep:
		return "sleep"
	case StepScreenshot:
		return "screenshot"
	case StepReadPage:
		return "text"
	}
	return s.Kind
}

// validateBrowser checks a browser journey. The rules are the same ones
// the HTTP engine enforces, in the vocabulary of a page.
func (m *Monitor) validateBrowser() error {
	navigated := false
	for i := range m.Steps {
		s := &m.Steps[i]
		switch s.Kind {
		case StepGoto:
			if s.URL == "" {
				return fmt.Errorf("step %q: a navigation needs a URL", s.Name)
			}
			navigated = true
		case StepClick, StepWaitFor:
			if s.Selector == "" {
				return fmt.Errorf("step %q: %s needs a selector", s.Name, s.Kind)
			}
		case StepFill:
			if s.Selector == "" {
				return fmt.Errorf("step %q: a fill needs a selector", s.Name)
			}
			if s.Value == "" {
				return fmt.Errorf("step %q: a fill needs a value", s.Name)
			}
		case StepPress:
			if s.Key == "" {
				return fmt.Errorf("step %q: a key press needs a key", s.Name)
			}
		case StepEval:
			if s.Expression == "" {
				return fmt.Errorf("step %q: an eval needs an expression", s.Name)
			}
		case StepSleep:
			if s.SleepMs <= 0 || s.SleepMs > 30_000 {
				return fmt.Errorf("step %q: a sleep waits between 1ms and 30s", s.Name)
			}
		case StepScreenshot, StepReadPage, StepAssert:
		default:
			return fmt.Errorf("step %q: %q is not a browser step", s.Name, s.Kind)
		}

		// A credential typed into a page is fine. A credential in a URL
		// is a credential in somebody's access log.
		if s.Kind == StepGoto && strings.Contains(s.URL, "{{ secrets.") {
			return fmt.Errorf("step %q: a credential may not appear in a URL", s.Name)
		}
		if s.Screenshot != nil {
			if err := s.Screenshot.validate(); err != nil {
				return fmt.Errorf("step %q: %w", s.Name, err)
			}
		}
		for _, a := range s.Assertions {
			if err := a.validate(); err != nil {
				return fmt.Errorf("step %q: %w", s.Name, err)
			}
		}
	}
	if !navigated {
		return errors.New("a browser journey needs at least one navigation")
	}
	return nil
}

func (c *ScreenshotCheck) validate() error {
	if c.Baseline != "" && len(c.Baseline) != 16 {
		return fmt.Errorf("a baseline is 16 hex characters, got %d", len(c.Baseline))
	}
	if c.MaxDistance < 0 || c.MaxDistance > 64 {
		return errors.New("a hash distance is between 0 and 64")
	}
	if c.MinInkPPM < 0 || c.MinInkPPM > 1_000_000 {
		return errors.New("an ink floor is between 0 and 1000000 parts per million")
	}
	switch c.Store {
	case "", StoreAlways, StoreOnFault, StoreNever:
	default:
		return fmt.Errorf("%q is not a storage rule", c.Store)
	}
	return nil
}

// Capture is a screenshot the engine produced and what was measured
// about it. The image travels to the caller for storage; the record
// keeps the measurements and the digest.
type Capture struct {
	Step   string `json:"step"`
	Digest string `json:"digest"`
	Hash   string `json:"hash"`
	InkPPM int64  `json:"ink_ppm"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Bytes  int    `json:"bytes"`
	// Distance is how far the capture is from the approved baseline, or
	// -1 when there is none to compare against yet.
	Distance int `json:"distance"`
	// Stored says whether the image itself was kept.
	Stored bool `json:"stored"`
	// PNG is the image. It is never serialised into the record: the
	// record holds the digest, and the sealed volume holds the bytes.
	PNG []byte `json:"-"`
}

// Summary renders a capture for a step's detail line, so a responder
// reading the reading sees the numbers without opening the image.
func (c Capture) Summary() string {
	out := fmt.Sprintf("%dx%d, %s ink", c.Width, c.Height, formatPPM(c.InkPPM))
	if c.Distance >= 0 {
		out += fmt.Sprintf(", %d bits from the baseline", c.Distance)
	}
	if c.Stored {
		out += ", kept"
	}
	return out
}

func formatPPM(ppm int64) string {
	return fmt.Sprintf("%d.%02d%%", ppm/10000, (ppm%10000)/100)
}

// FormatInk renders an ink measurement as a percentage.
func FormatInk(ppm int64) string { return formatPPM(ppm) }
