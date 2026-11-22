// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"fmt"
	"testing"
)

// MeasuredOverhead returns the expected overhead or zero for an unsupported version.
func MeasuredOverhead(version int) int {
	switch {
	case version >= 1 && version <= 9:
		return 191
	case version >= 10 && version <= 99:
		// Measured at 10 and 11. The header can show the decimal version,
		// and the overhead grew by one byte when the version gained a digit.
		// Apply the same rule through 99.
		return 192
	default:
		return 0
	}
}

func checkCiphertextLength(t *testing.T, version, plaintextBytes, ciphertextBytes int) {
	t.Helper()
	if err := ciphertextLengthError(version, plaintextBytes, ciphertextBytes); err != nil {
		t.Fatal(err)
	}
}

func checkCiphertextLengthAs(t *testing.T, label string, version, plaintextBytes, ciphertextBytes int) {
	t.Helper()
	if err := ciphertextLengthError(version, plaintextBytes, ciphertextBytes); err != nil {
		t.Errorf("%s: %v", label, err)
	}
}

func ciphertextLengthError(version, plaintextBytes, ciphertextBytes int) error {
	switch overhead := MeasuredOverhead(version); {
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
func MeasuredCiphertextLength(plaintextBytes, ciphertextBytes int) bool {
	switch ciphertextBytes - plaintextBytes {
	case MeasuredOverhead(1), MeasuredOverhead(10):
		return true
	default:
		return false
	}
}
