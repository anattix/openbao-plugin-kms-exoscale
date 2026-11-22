// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"strings"
	"testing"
)

func TestMeasuredOverhead(t *testing.T) {
	for _, tc := range []struct {
		version, overhead int
	}{
		{0, 0}, {1, 191}, {9, 191}, {10, 192}, {11, 192}, {12, 192}, {99, 192}, {100, 0},
	} {
		if got := MeasuredOverhead(tc.version); got != tc.overhead {
			t.Errorf("material version %d: got overhead %d, want %d", tc.version, got, tc.overhead)
		}
	}
}

func TestMeasuredCiphertextLength(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		plaintext, ciphertext int
		want                  bool
	}{
		{"one digit", 32, 223, true},
		{"two digits", 32, 224, true},
		{"short", 32, 222, false},
		{"long", 32, 225, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if MeasuredCiphertextLength(tc.plaintext, tc.ciphertext) != tc.want {
				t.Fatal("observed-length check did not match the fixture")
			}
		})
	}
}

func TestCiphertextLengthRequiresSupportedVersion(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    int
		diagnostic string
	}{
		{"missing", 0, "material version missing or invalid"},
		{"unmeasured", 100, "overhead unmeasured at material version 100: observed 193"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ciphertextLengthError(tc.version, 32, 225)
			if err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
				t.Errorf("missing diagnostic %q for material version %d", tc.diagnostic, tc.version)
			}
		})
	}
}
