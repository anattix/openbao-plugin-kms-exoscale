// SPDX-License-Identifier: MPL-2.0

package main

import (
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

func TestConfigRefusesExistingRelativeFile(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("fixture", []byte("file-fixture"), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	_, err := resolveConfig(t.Context(), wrapping.WithDisallowEnvVars(true), wrapping.WithKeyId(testkms.KeyID), wrapping.WithConfigMap(map[string]string{
		"zone": testkms.Zone, "api_key": "file://fixture", "api_secret": "file://fixture"}))
	if err == nil {
		t.Fatal("relative credential path was accepted")
	}
}

func TestPluginRejectsTamperedEnvelope(t *testing.T) {
	var attempts atomic.Int32
	cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, _ *http.Request, op string) bool {
		if op == "decrypt" {
			attempts.Add(1)
		}
		return false
	})
	remote := pluginClient(t, "TestServer")
	ctx := t.Context()
	if err := configureRemote(ctx, remote, cfg.KeyID, endpoint); err != nil {
		t.Fatal("configure tamper probe:", err)
	}
	blob, err := remote.Encrypt(ctx, []byte("synthetic seal fixture"))
	if err != nil {
		t.Fatal("encrypt tamper probe:", err)
	}

	blob.Ciphertext[0] ^= 1
	plaintext, err := remote.Decrypt(ctx, blob)
	defer clear(plaintext)
	if err == nil || !strings.Contains(err.Error(), "request failed or invalid response") || len(plaintext) != 0 {
		t.Fatal("tampered envelope did not produce a sanitized error without plaintext")
	}
	if attempts.Load() != 1 {
		t.Fatal("tampered envelope must make exactly one KMS decrypt call")
	}
}
