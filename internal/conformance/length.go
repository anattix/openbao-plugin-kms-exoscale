// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// EndpointZone extracts the issuing zone from a standard Exoscale API hostname.
func EndpointZone(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	host, ok := strings.CutSuffix(strings.ToLower(u.Hostname()), ".exoscale.com")
	if !ok {
		return ""
	}
	zone, ok := strings.CutPrefix(host, "api-")
	if !ok {
		return ""
	}
	return zone
}

// MeasuredOverhead returns the expected overhead or zero for an unsupported version.
func MeasuredOverhead(zone string, version int) int {
	// The two measured zones differed by one byte on the same version.
	// Keep the origin baseline for other zones until there is evidence for them.
	base := 191
	if zone == "ch-dk-2" {
		base--
	}
	switch {
	case version >= 1 && version <= 9:
		return base
	case version >= 10 && version <= 99:
		// Measured at 10 and 11. The header can show the decimal version,
		// and the overhead grew by one byte when the version gained a digit.
		// Apply the same rule through 99.
		return base + 1
	default:
		return 0
	}
}

func checkCiphertextLength(t *testing.T, zone string, version, plaintextBytes, ciphertextBytes int) {
	t.Helper()
	if err := ciphertextLengthError(zone, version, plaintextBytes, ciphertextBytes); err != nil {
		t.Fatal(err)
	}
}

func checkCiphertextLengthAs(t *testing.T, label string, zone string, version, plaintextBytes, ciphertextBytes int) {
	t.Helper()
	if err := ciphertextLengthError(zone, version, plaintextBytes, ciphertextBytes); err != nil {
		t.Errorf("%s: %v", label, err)
	}
}

func ciphertextLengthError(zone string, version, plaintextBytes, ciphertextBytes int) error {
	switch overhead := MeasuredOverhead(zone, version); {
	case version < 1:
		return fmt.Errorf("KMS material version missing or invalid (%d); length assertions cannot run", version)
	case overhead == 0:
		return fmt.Errorf("KMS ciphertext overhead unmeasured at material version %d: observed %d", version, ciphertextBytes-plaintextBytes)
	case ciphertextBytes == 0:
		return fmt.Errorf("missing ciphertext")
	case ciphertextBytes != plaintextBytes+overhead:
		return fmt.Errorf("ciphertext overhead at material version %d with %d plaintext bytes: got %d, want %d",
			version, plaintextBytes, ciphertextBytes-plaintextBytes, overhead)
	default:
		return nil
	}
}

// MeasuredCiphertextLength checks the overhead seen on paths where the
// emitting material version is not available, such as provider-only IAM.
func MeasuredCiphertextLength(zone string, plaintextBytes, ciphertextBytes int) bool {
	switch ciphertextBytes - plaintextBytes {
	case MeasuredOverhead(zone, 1), MeasuredOverhead(zone, 10):
		return true
	default:
		return false
	}
}
