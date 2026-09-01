// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package visual decides what a screenshot means, deterministically.
//
// The temptation with screenshots is to ask a model whether the page
// looks right. That would be a mistake here, and not because of cost: a
// report's whole claim is that its arithmetic recomputes from the
// evidence it carries, and a model's judgement does not reproduce. An
// availability figure that rests on one is a figure nobody can check,
// which is the thing this product exists to replace.
//
// So the checks in this package are arithmetic over pixels: is anything
// there at all, and does it still look like what somebody approved. Both
// answers are integers, both are re-derivable by anyone holding the
// image, and both are wrong in obvious ways rather than subtle ones. A
// model is useful afterwards, for explaining a difference to a human;
// it is not useful for deciding whether the month was met.
package visual

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"math/bits"
	"sort"
)

// Digest is the content hash of an image, which is what goes in the
// record. The image itself lives on the sealed volume under the same
// retention as the readings.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Region is a rectangle in image coordinates, used to exclude the parts
// of a page that legitimately change: a clock, a carousel, a "last
// updated" line. A baseline without them is a baseline that fails every
// minute and teaches everyone to ignore it.
type Region struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

// Analysis is everything this package can say about one screenshot.
type Analysis struct {
	Digest string `json:"digest"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Bytes  int    `json:"bytes"`
	// Hash is a 64-bit perceptual hash, hex encoded. Two images of the
	// same page differ in a handful of bits; two different pages differ
	// in dozens.
	Hash string `json:"hash"`
	// InkPPM is how much of the image is not the background colour, in
	// parts per million. A page that rendered nothing is near zero, and
	// that is the single most useful thing a screenshot tells you.
	InkPPM int64 `json:"ink_ppm"`
	// UniqueColours is capped and reported for context. It is not part
	// of the blank decision: a page of pure black text on white is two
	// colours and perfectly fine, while a full-page error panel is
	// already caught by the ink measure, because the panel becomes the
	// background that everything else is measured against.
	UniqueColours int `json:"unique_colours"`
}

// Blank reports whether the image is empty enough that nothing useful
// rendered.
func (a Analysis) Blank(floorPPM int64) bool {
	if floorPPM <= 0 {
		floorPPM = DefaultInkFloorPPM
	}
	return a.InkPPM < floorPPM
}

// DefaultInkFloorPPM is the default threshold for "nothing rendered".
//
// Measured against real pages: a sparse one (a heading, a button, a
// line of text) comes out around 1%, and a dense one several times
// that. A blank page is essentially zero, and so is a page that is one
// solid colour, because the colour becomes the background everything
// else is measured against. The floor sits well below the sparse case
// on purpose: this is an emptiness detector, not a content check, and a
// threshold that fires on a thin page teaches everyone to ignore it.
const DefaultInkFloorPPM = 1_000

// Analyse computes everything about one screenshot in a single decode.
func Analyse(raw []byte, masks []Region) (Analysis, error) {
	out := Analysis{Digest: Digest(raw), Bytes: len(raw)}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return out, fmt.Errorf("visual: the capture is not a decodable image: %w", err)
	}
	bounds := img.Bounds()
	out.Width, out.Height = bounds.Dx(), bounds.Dy()
	if out.Width == 0 || out.Height == 0 {
		return out, fmt.Errorf("visual: the capture has no pixels")
	}

	masked := newMask(bounds, masks)
	grey := toGrey(img, masked)

	out.Hash = hex.EncodeToString(perceptualHash(grey))
	out.InkPPM, out.UniqueColours = ink(img, masked)
	return out, nil
}

// Distance is the Hamming distance between two perceptual hashes: the
// number of bits that differ. Identical renderings are 0; the same page
// with different content in it is a handful; a different page is dozens.
func Distance(a, b string) (int, error) {
	x, err := hex.DecodeString(a)
	if err != nil || len(x) != 8 {
		return 0, fmt.Errorf("visual: %q is not a 64-bit hash", a)
	}
	y, err := hex.DecodeString(b)
	if err != nil || len(y) != 8 {
		return 0, fmt.Errorf("visual: %q is not a 64-bit hash", b)
	}
	total := 0
	for i := range x {
		total += bits.OnesCount8(x[i] ^ y[i])
	}
	return total, nil
}

// DefaultDistance is the default tolerance against a baseline. Anti
// aliasing and a changed number move a couple of bits; a redesign, a
// blank page or a consent wall move many more.
const DefaultDistance = 8

// mask is the set of pixels excluded from every measurement.
type mask struct {
	bounds image.Rectangle
	rects  []image.Rectangle
}

func newMask(bounds image.Rectangle, regions []Region) *mask {
	m := &mask{bounds: bounds}
	for _, r := range regions {
		if r.W <= 0 || r.H <= 0 {
			continue
		}
		m.rects = append(m.rects, image.Rect(
			bounds.Min.X+r.X, bounds.Min.Y+r.Y,
			bounds.Min.X+r.X+r.W, bounds.Min.Y+r.Y+r.H))
	}
	return m
}

func (m *mask) excluded(x, y int) bool {
	for _, r := range m.rects {
		if x >= r.Min.X && x < r.Max.X && y >= r.Min.Y && y < r.Max.Y {
			return true
		}
	}
	return false
}

// hashSize is the side of the reduced image the perceptual hash is
// computed over: 32x32 down to an 8x8 signature via the low-frequency
// corner of a discrete cosine transform.
const hashSize = 32
const hashBits = 8

// toGrey reduces the image to a hashSize square of luminance, which is
// what the transform below runs over. Masked pixels take the image's
// mean so they contribute nothing but do not create an edge.
func toGrey(img image.Image, m *mask) [][]float64 {
	bounds := img.Bounds()
	out := make([][]float64, hashSize)
	var sum float64
	var count int

	for y := 0; y < hashSize; y++ {
		out[y] = make([]float64, hashSize)
		for x := 0; x < hashSize; x++ {
			sx := bounds.Min.X + x*bounds.Dx()/hashSize
			sy := bounds.Min.Y + y*bounds.Dy()/hashSize
			if m.excluded(sx, sy) {
				out[y][x] = math.NaN()
				continue
			}
			r, g, b, _ := img.At(sx, sy).RGBA()
			// Rec. 601 luma, which is what a person's eye weights.
			lum := 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(b>>8)
			out[y][x] = lum
			sum += lum
			count++
		}
	}
	mean := 0.0
	if count > 0 {
		mean = sum / float64(count)
	}
	for y := range out {
		for x := range out[y] {
			if math.IsNaN(out[y][x]) {
				out[y][x] = mean
			}
		}
	}
	return out
}

// perceptualHash is the classic DCT hash: transform, keep the
// low-frequency corner, and record which coefficients are above the
// median. It is stable against re-encoding and small rendering
// differences, and moves sharply when the layout does.
func perceptualHash(grey [][]float64) []byte {
	dct := make([][]float64, hashSize)
	for u := 0; u < hashSize; u++ {
		dct[u] = make([]float64, hashSize)
		for v := 0; v < hashSize; v++ {
			var sum float64
			for y := 0; y < hashSize; y++ {
				for x := 0; x < hashSize; x++ {
					sum += grey[y][x] *
						math.Cos(float64(2*x+1)*float64(u)*math.Pi/(2*hashSize)) *
						math.Cos(float64(2*y+1)*float64(v)*math.Pi/(2*hashSize))
				}
			}
			dct[u][v] = sum * alpha(u) * alpha(v)
		}
	}

	values := make([]float64, 0, hashBits*hashBits)
	for u := 0; u < hashBits; u++ {
		for v := 0; v < hashBits; v++ {
			values = append(values, dct[u][v])
		}
	}
	// The first coefficient is the average brightness and swamps the
	// median, so it is excluded from it.
	ordered := append([]float64(nil), values[1:]...)
	sort.Float64s(ordered)
	median := ordered[len(ordered)/2]

	out := make([]byte, 8)
	for i, v := range values {
		if v > median {
			out[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return out
}

func alpha(u int) float64 {
	if u == 0 {
		return math.Sqrt(1.0 / float64(hashSize))
	}
	return math.Sqrt(2.0 / float64(hashSize))
}

// ink measures how much of the image differs from its most common
// colour, and how many distinct colours it holds. Between them they
// separate "a rendered page", "a blank page" and "one large coloured
// panel", which are the three outcomes worth telling apart.
func ink(img image.Image, m *mask) (ppm int64, unique int) {
	bounds := img.Bounds()
	// Sample rather than read every pixel: at a stride of two in each
	// direction the figures are the same to well within the thresholds,
	// at a quarter of the work.
	const stride = 2
	counts := map[color.RGBA]int{}
	total := 0

	for y := bounds.Min.Y; y < bounds.Max.Y; y += stride {
		for x := bounds.Min.X; x < bounds.Max.X; x += stride {
			if m.excluded(x, y) {
				continue
			}
			r, g, b, _ := img.At(x, y).RGBA()
			// Quantise: a gradient is not a hundred thousand colours for
			// this purpose, and anti-aliasing is not content.
			key := color.RGBA{
				R: uint8(r >> 8 & 0xf0), G: uint8(g >> 8 & 0xf0), B: uint8(b >> 8 & 0xf0), A: 255,
			}
			counts[key]++
			total++
			if len(counts) > 4096 {
				// Enough to know it is not a blank page.
				break
			}
		}
	}
	if total == 0 {
		return 0, 0
	}

	background, most := color.RGBA{}, 0
	for c, n := range counts {
		if n > most {
			background, most = c, n
		}
	}
	_ = background
	foreground := total - most
	return int64(foreground) * 1_000_000 / int64(total), len(counts)
}
