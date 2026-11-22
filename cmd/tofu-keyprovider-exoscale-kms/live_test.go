// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func TestLiveProvider(t *testing.T) {
	cfg := conformance.LiveConfig(t)
	t.Run("provider_roundtrip", func(t *testing.T) {
		first, _ := providerRoundTrip(t, cfg)
		t.Logf("KMS provider_roundtrip key_bytes=32 wrapped_bytes=%d", len(first.Meta.ExternalData.WrappedKey))
	})
	t.Run("provider_context", func(t *testing.T) {
		providerContextCases(t, cfg, "")
		t.Log("KMS provider_context same=200 absent=400 different=400 added=400")
	})
	if os.Getenv("EXOSCALEKMS_LIVE_LEAST_PRIVILEGE") == "1" {
		t.Run("least_privilege", func(t *testing.T) {
			client, _, err := providerLoad(t, cfg)(t.Context())
			if err != nil {
				t.Fatal("configure state role probe")
			}
			_, err = client.Encrypt(t.Context(), cfg.KeyID, make([]byte, kmsapi.KeySize))
			var status *kmsapi.StatusError
			if !errors.As(err, &status) || status.Code != http.StatusForbidden {
				t.Fatal("state role must deny encrypt with HTTP 403")
			}
			t.Log("KMS provider_least_privilege generate=200 decrypt=200 encrypt=403")
		})
	}
}

func providerLoad(t *testing.T, cfg kmsapi.Config) func(context.Context) (*kmsapi.Client, kmsapi.Config, error) {
	t.Helper()
	client, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal("configure provider probe")
	}
	return func(context.Context) (*kmsapi.Client, kmsapi.Config, error) { return client, cfg, nil }
}

func providerRoundTrip(t *testing.T, cfg kmsapi.Config) (output, []byte) {
	t.Helper()
	load := providerLoad(t, cfg)
	first := exchange(t, []byte("null"), load)
	t.Cleanup(func() { clear(first.Keys.Encryption) })
	meta, err := json.Marshal(first.Meta)
	if err != nil {
		t.Fatal("encode provider metadata")
	}
	second := exchange(t, meta, load)
	defer clear(second.Keys.Encryption)
	defer clear(second.Keys.Decryption)
	if !conformance.MeasuredCiphertextLength(kmsapi.KeySize, len(first.Meta.ExternalData.WrappedKey)) {
		t.Error("first provider wrap is outside the measured lengths")
	}
	if !conformance.MeasuredCiphertextLength(kmsapi.KeySize, len(second.Meta.ExternalData.WrappedKey)) {
		t.Error("second provider wrap is outside the measured lengths")
	}
	if t.Failed() || len(first.Keys.Encryption) != kmsapi.KeySize ||
		!bytes.Equal(first.Keys.Encryption, second.Keys.Decryption) || bytes.Equal(first.Keys.Encryption, second.Keys.Encryption) {
		t.Fatal("provider must read the old state key and generate a fresh key with the measured lengths")
	}
	return first, meta
}
