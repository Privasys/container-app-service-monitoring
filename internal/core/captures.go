// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Screenshots.
//
// The measurements go in the ledger with the reading: the digest, the
// perceptual hash, how much of the image was not background, how far it
// was from the approved baseline. Those are what an availability
// verdict rests on and what a verifier recomputes, and they are small.
//
// The image itself goes on the sealed volume, addressed by its own
// digest, because a picture is what a responder actually wants to look
// at and no arithmetic replaces it. Keeping it addressed by digest
// means the record's reference to it is a commitment: a substituted
// image is a different file with a different name, and the reading
// still points at the one that was taken.
//
// They are kept sparingly. A monitor capturing every thirty seconds for
// a year is a million pictures of a page that was fine; the default is
// to keep the ones where something went wrong or the page changed.

// screenshotDir is where images live under the sealed volume.
const screenshotDir = "screenshots"

// storeCaptures writes the images a reading produced and returns the
// captures with their bytes dropped, ready for the record.
func (m *Monitor) storeCaptures(captures []model.Capture) []model.Capture {
	if len(captures) == 0 {
		return nil
	}
	out := make([]model.Capture, 0, len(captures))
	for _, c := range captures {
		if c.Stored && len(c.PNG) > 0 {
			if err := m.writeScreenshot(c.Digest, c.PNG); err != nil {
				// A picture that could not be kept is not a failure of the
				// watched service, and not a reason to lose the reading. The
				// record says the image is not there rather than implying it
				// is.
				c.Stored = false
			}
		}
		c.PNG = nil
		out = append(out, c)
	}
	return out
}

func (m *Monitor) writeScreenshot(digest string, png []byte) error {
	if m.opts.DataDir == "" {
		return fmt.Errorf("core: no data directory for screenshots")
	}
	if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 {
		return fmt.Errorf("core: %q is not a digest", digest)
	}
	// Two levels of fan-out, so a directory listing stays usable after a
	// year of incidents.
	dir := filepath.Join(m.opts.DataDir, screenshotDir, digest[:2], digest[2:4])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, digest+".png")
	if _, err := os.Stat(path); err == nil {
		// Content addressed: the same picture twice is one file, which is
		// the common case for a page that has not changed.
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, png, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Screenshot returns a stored image by digest.
func (m *Monitor) Screenshot(digest string) ([]byte, error) {
	if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 {
		return nil, fmt.Errorf("core: %q is not a digest", digest)
	}
	path := filepath.Join(m.opts.DataDir, screenshotDir, digest[:2], digest[2:4], digest+".png")
	return os.ReadFile(path)
}

// pruneScreenshots removes images no surviving reading refers to.
//
// It runs after the readings themselves are pruned, so the set of
// digests still referenced is the set still in the record. An image
// nobody points at is not evidence of anything.
func (m *Monitor) pruneScreenshots(referenced map[string]bool) (int, error) {
	root := filepath.Join(m.opts.DataDir, screenshotDir)
	if _, err := os.Stat(root); err != nil {
		return 0, nil
	}
	removed := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".png") {
			return nil
		}
		digest := strings.TrimSuffix(name, ".png")
		if referenced[digest] {
			return nil
		}
		if err := os.Remove(path); err == nil {
			removed++
		}
		return nil
	})
	return removed, err
}
