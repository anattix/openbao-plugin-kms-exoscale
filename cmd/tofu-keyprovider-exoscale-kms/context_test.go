// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

func TestEncryptionContext(t *testing.T) {
	cfg := testkms.Start(t, nil)
	t.Setenv("EXOSCALEKMS_ENCRYPTION_CONTEXT", "stack-a")
	resolved, err := kmsapi.Resolve(t.Context(), map[string]string{"zone": cfg.Zone}, cfg.KeyID, false)
	if err != nil || resolved.EncryptionContext != "stack-a" {
		t.Fatal("provider environment context was not resolved")
	}
	providerContextCases(t, cfg, "#/crypto/invalid-ciphertext")
}

func providerContextCases(t *testing.T, cfg kmsapi.Config, modelledType string) {
	t.Helper()
	cfg.EncryptionContext = "stack-a"
	_, bound := providerRoundTrip(t, cfg)
	cfg.EncryptionContext = ""
	_, legacy := providerRoundTrip(t, cfg)
	for _, tc := range []struct {
		name, context string
		meta          []byte
	}{
		{"absent", "", bound}, {"different", "stack-b", bound}, {"added", "stack-a", legacy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.EncryptionContext = tc.context
			var stdout bytes.Buffer
			err := run(t.Context(), bytes.NewReader(tc.meta), &stdout, providerLoad(t, cfg))
			var status *kmsapi.StatusError
			if !errors.As(err, &status) || status.Code != http.StatusBadRequest ||
				stdout.String() != headerLine {
				t.Fatal("wrong context must fail with HTTP 400 and only the protocol header")
			}
			if modelledType != "" && status.ProblemType != modelledType {
				t.Fatal("wrong context lost the fake's known problem type")
			}
			t.Logf("KMS provider_context_mismatch status=400 type=%s", kmsapi.SafeProblemType(status.ProblemType))
		})
	}
}

func TestLegacyProviderWire(t *testing.T) {
	raw := bytes.Repeat([]byte{17}, kmsapi.KeySize)
	defer clear(raw)
	key := []byte{1, 2, 3}
	cfg := testkms.Start(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
		body, err := io.ReadAll(r.Body)
		defer clear(body)
		var want string
		switch op {
		case "decrypt":
			want = `{"ciphertext":"AQID"}`
		case "generate-data-key":
			want = `{"key-spec":"AES-256"}`
		}
		if err != nil || string(body) != want {
			t.Error("unset context changed the base request JSON")
		}
		if err := json.NewEncoder(w).Encode(struct {
			Plaintext  []byte `json:"plaintext"`
			Ciphertext []byte `json:"ciphertext"`
		}{raw, key}); err != nil {
			t.Error("write synthetic KMS reply")
		}
		return true
	})
	legacy := []byte(`{"external_data":{"version":1,"key_id":"` + cfg.KeyID + `","wrapped_key":"AQID"}}`)
	got := exchange(t, legacy, providerLoad(t, cfg))
	defer clear(got.Keys.Decryption)
	defer clear(got.Keys.Encryption)
	want, err := hkdf.Key(sha256.New, raw, nil, "exoscalekms/opentofu/state-key/v1", kmsapi.KeySize)
	defer clear(want)
	encoded, encodeErr := json.Marshal(got.Meta)
	if err != nil || encodeErr != nil || !bytes.Equal(encoded, legacy) ||
		!bytes.Equal(got.Keys.Encryption, want) || !bytes.Equal(got.Keys.Decryption, want) {
		t.Fatal("base metadata or base HKDF contract changed")
	}
}

func TestProviderWrappedLengthsAcrossRotation(t *testing.T) {
	cfg, _, rotate := testkms.StartWithRotation(t)
	for range 8 {
		rotate()
	}
	first, meta := providerRoundTrip(t, cfg)
	if len(first.Meta.ExternalData.WrappedKey) != 223 {
		t.Fatal("version 9 provider metadata must wrap the key to 223 bytes")
	}
	rotate()
	next := exchange(t, meta, providerLoad(t, cfg))
	defer clear(next.Keys.Encryption)
	defer clear(next.Keys.Decryption)
	if len(next.Meta.ExternalData.WrappedKey) != 224 || !bytes.Equal(first.Keys.Encryption, next.Keys.Decryption) {
		t.Fatal("version 10 provider metadata must wrap to 224 bytes and recover the version 9 state key")
	}
	providerRoundTrip(t, cfg)
}

// TestProviderRejectsSkewedWrappedLength requires the provider round trip shared
// with the live suite to reject a valid wrap two bytes longer than measured.
func TestProviderRejectsSkewedWrappedLength(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_PROVIDER_SKEW_CHILD"
	if os.Getenv(child) == "1" {
		cfg, _ := testkms.StartWithOverheadSkew(t, 2)
		providerRoundTrip(t, cfg)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestProviderRejectsSkewedWrappedLength$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("first provider wrap is outside the measured lengths")) ||
		!bytes.Contains(out, []byte("second provider wrap is outside the measured lengths")) {
		t.Fatal("provider round trip accepted a skewed wrapped key")
	}
}
