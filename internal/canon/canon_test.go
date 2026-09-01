// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package canon

import (
	"encoding/json"
	"testing"
)

func TestMemberOrderDoesNotChangeTheBytes(t *testing.T) {
	a := map[string]any{"b": 1, "a": 2, "z": map[string]any{"y": 3, "x": 4}}
	b := map[string]any{"z": map[string]any{"x": 4, "y": 3}, "a": 2, "b": 1}
	if string(MustMarshal(a)) != string(MustMarshal(b)) {
		t.Fatalf("member order changed the encoding:\n  %s\n  %s", MustMarshal(a), MustMarshal(b))
	}
	if got, want := string(MustMarshal(a)), `{"a":2,"b":1,"z":{"x":4,"y":3}}`; got != want {
		t.Errorf("encoding = %s, want %s", got, want)
	}
}

func TestIntegersKeepTheirForm(t *testing.T) {
	// A JSON round trip turns every number into a float64, and a
	// transaction id is a hash over these bytes: a version that encodes
	// as 3 in one process and 3e+00 in another would break every proof.
	var decoded any
	if err := json.Unmarshal([]byte(`{"version":3,"big":9007199254740991,"ratio":0.5}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if got, want := string(MustMarshal(decoded)), `{"big":9007199254740991,"ratio":0.5,"version":3}`; got != want {
		t.Errorf("encoding = %s, want %s", got, want)
	}
}

func TestStringEscaping(t *testing.T) {
	control := string(rune(1))
	newline := string(rune(10))
	quote := `"`
	backslash := string(rune(92))
	cases := []struct{ in, want string }{
		{"plain", `"plain"`},
		{"a" + quote + "b", `"a\"b"`},
		{"a" + backslash + "b", `"a\\b"`},
		{"line" + newline + "end", `"line\nend"`},
		{control, quote + backslash + "u0001" + quote},
		{"héllo", `"héllo"`},
		{"<tag>", `"<tag>"`},
	}
	for _, c := range cases {
		if got := string(MustMarshal(c.in)); got != c.want {
			t.Errorf("Marshal(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestUnsupportedTypesAreRejected(t *testing.T) {
	if _, err := Marshal(map[string]any{"x": complex(1, 2)}); err == nil {
		t.Error("expected an unsupported type to be refused")
	}
}
