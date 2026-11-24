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
		for _, zone := range []string{"ch-gva-2", "ch-dk-2"} {
			want := tc.overhead
			if want != 0 && zone == "ch-dk-2" {
				want--
			}
			if got := MeasuredOverhead(zone, tc.version); got != want {
				t.Errorf("%s material version %d: got overhead %d, want %d", zone, tc.version, got, want)
			}
		}
	}
}

func TestMeasuredCiphertextLength(t *testing.T) {
	for _, tc := range []struct {
		name, zone            string
		plaintext, ciphertext int
		want                  bool
	}{
		{"origin one digit", "ch-gva-2", 32, 223, true},
		{"origin two digits", "ch-gva-2", 32, 224, true},
		{"origin short", "ch-gva-2", 32, 222, false},
		{"origin long", "ch-gva-2", 32, 225, false},
		{"replica one digit", "ch-dk-2", 32, 222, true},
		{"replica two digits", "ch-dk-2", 32, 223, true},
		{"replica short", "ch-dk-2", 32, 221, false},
		{"replica long", "ch-dk-2", 32, 224, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if MeasuredCiphertextLength(tc.zone, tc.plaintext, tc.ciphertext) != tc.want {
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
			err := ciphertextLengthError("ch-dk-2", tc.version, 32, 225)
			if err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
				t.Errorf("missing diagnostic %q for material version %d", tc.diagnostic, tc.version)
			}
		})
	}
}

func TestEndpointZone(t *testing.T) {
	for _, tc := range []struct{ endpoint, zone string }{
		{"https://api-ch-gva-2.exoscale.com/v2", "ch-gva-2"},
		{"https://API-CH-DK-2.exoscale.com:443/v2/", "ch-dk-2"},
		{"https://api-ch-dk-2.exoscale.com.example.test/v2", ""},
		{"https://ch-dk-2.exoscale.com/v2", ""},
		{"https://%invalid/v2", ""},
		{"", ""},
	} {
		if got := EndpointZone(tc.endpoint); got != tc.zone {
			t.Errorf("endpoint %q: got zone %q, want %q", tc.endpoint, got, tc.zone)
		}
	}
}

func TestCiphertextLengthUsesZoneAndVersion(t *testing.T) {
	for _, tc := range []struct {
		zone              string
		version, overhead int
		want              bool
	}{
		{"ch-gva-2", 1, 191, true},
		{"ch-dk-2", 1, 190, true},
		{"ch-dk-2", 1, 191, false},
		{"ch-dk-2", 9, 190, true},
		{"ch-dk-2", 10, 190, false},
		{"ch-dk-2", 10, 191, true},
		{"ch-dk-2", 99, 191, true},
		{"ch-gva-2", 10, 192, true},
		{"ch-gva-2", 10, 191, false},
	} {
		if ok := ciphertextLengthError(tc.zone, tc.version, 32, 32+tc.overhead) == nil; ok != tc.want {
			t.Errorf("%s version %d overhead %d: length accepted = %t, want %t", tc.zone, tc.version, tc.overhead, ok, tc.want)
		}
	}
}
