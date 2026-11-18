// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package mail

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// WarnDays are how many days before the certificate expires its operators
// are told. A certificate that lapses silently stops every alert email.
var WarnDays = []int{60, 30}

// DueWarning returns the warning owed at now, if any: the nearest threshold
// already crossed, unless it was given. A monitor that was down through the
// 60-day mark warns once at the next one rather than twice.
func DueWarning(notAfter, now time.Time, warned []int) (int, bool) {
	left := notAfter.Sub(now)
	due := 0
	for _, d := range WarnDays {
		if left <= time.Duration(d)*24*time.Hour && (due == 0 || d < due) {
			due = d
		}
	}
	if due == 0 || slices.Contains(warned, due) {
		return 0, false
	}
	return due, true
}

// LoadWarned reads which warnings were given for the certificate in dir.
func LoadWarned(dir string) ([]int, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "warned.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	var out []int
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	return out, nil
}

// SaveWarned records which warnings were given, so a restart does not
// repeat them.
func SaveWarned(dir string, warned []int) error {
	raw, err := json.Marshal(warned)
	if err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "warned.json"), raw, 0o600); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	return nil
}
