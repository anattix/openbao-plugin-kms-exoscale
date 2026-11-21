// SPDX-License-Identifier: MPL-2.0

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	upstream "github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

func TestConfigRouting(t *testing.T) {
	t.Setenv(upstream.EnvExoscaleApiKey, "test-only")
	t.Setenv(upstream.EnvExoscaleApiSecret, "test-only")
	t.Setenv(upstream.EnvExoscaleKmsKeyId, testkms.KeyID)
	t.Setenv(upstream.EnvExoscaleKmsZone, "")
	t.Setenv(upstream.EnvExoscaleKmsEndpoint, "")
	for _, tc := range []struct {
		name, zone, endpoint, key, want, errorText string
	}{
		{"Geneva", "ch-gva-2", "", "", "https://api-ch-gva-2.exoscale.com/v2", ""},
		{"ch-dk-2", "ch-dk-2", "", "", "https://api-ch-dk-2.exoscale.com/v2", ""},
		{"explicit HTTPS", "", "https://kms.example.test:8443/v2/", "", "https://kms.example.test:8443/v2", ""},
		{"extra endpoint path", "", "https://kms.example.test/v2/extra", "", "", "endpoint path must be /v2"},
		{"invalid zone and explicit endpoint", "not-a-zone", "https://kms.example.test/v2", "", "", "valid Exoscale KMS zone"},
		{"invalid zone", "ch-gva-2.example.test/", "", "", "", "valid Exoscale KMS zone"},
		{"HTTP", "", "http://kms.example.test/v2", "", "", "endpoint must be HTTPS"},
		{"relative", "", "/v2", "", "", "endpoint must be HTTPS"},
		{"missing host", "", "https:///v2", "", "", "endpoint must be HTTPS"},
		{"userinfo", "", "https://fixture@kms.example.test/v2", "", "", "without credentials"},
		{"query", "", "https://kms.example.test/v2?a=b", "", "", "without credentials"},
		{"fragment", "", "https://kms.example.test/v2#", "", "", "without credentials"},
		{"invalid key", "ch-gva-2", "", "invalid/uuid", "", "valid Exoscale KMS key UUID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.key != "" {
				t.Setenv(upstream.EnvExoscaleKmsKeyId, tc.key)
			}
			cfg, err := resolveConfig(t.Context(), wrapping.WithConfigMap(map[string]string{
				"zone": tc.zone, "endpoint": tc.endpoint, "key_id": testkms.OtherID,
			}))
			if tc.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errorText) {
					t.Fatal("expected routing validation failure:", tc.errorText)
				}
				return
			}
			if err != nil || cfg["endpoint"] != tc.want || cfg["key_id"] != testkms.KeyID {
				t.Fatal("expected HTTPS endpoint and environment UUID override:", tc.want)
			}
		})
	}
}

func TestConfigCredentialSources(t *testing.T) {
	t.Setenv(upstream.EnvExoscaleApiKey, "env-fixture")
	t.Setenv(upstream.EnvExoscaleApiSecret, "env-fixture")
	t.Setenv(upstream.EnvExoscaleKmsKeyId, "")
	t.Setenv(upstream.EnvExoscaleKmsZone, "")
	t.Setenv(upstream.EnvExoscaleKmsEndpoint, "")
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("file-fixture"), 0600); err != nil {
		t.Fatal("write credential fixture")
	}
	newline := filepath.Join(t.TempDir(), "newline")
	if err := os.WriteFile(newline, []byte("file-fixture\n"), 0600); err != nil {
		t.Fatal("write credential fixture")
	}
	for _, tc := range []struct {
		name, reference, want string
		disallow              bool
	}{
		{"file under disallow env", "file://" + path, "file-fixture", true},
		{"environment takes precedence", "file://" + path, "env-fixture", false},
		{"missing file", "file://" + path + "-missing", "", true},
		{"file with trailing newline", "file://" + newline, "", true},
		{"relative file", "file://relative", "", true},
		{"literal", "configured-fixture", "", true},
		{"forbidden environment reference", "env://EXOSCALE_API_SECRET", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := resolveConfig(t.Context(), wrapping.WithKeyId(testkms.KeyID),
				wrapping.WithConfigMap(map[string]string{"zone": testkms.Zone,
					"api_key": tc.reference, "api_secret": tc.reference}), wrapping.WithDisallowEnvVars(tc.disallow))
			if tc.want == "" {
				if err == nil {
					t.Fatal("unsafe or unreadable credential source was accepted")
				}
			} else if err != nil || cfg["api_key"] != tc.want || cfg["api_secret"] != tc.want {
				t.Fatal("wrong credential source selected")
			}
		})
	}
	t.Setenv(upstream.EnvExoscaleApiKey, "")
	t.Setenv(upstream.EnvExoscaleApiSecret, "")
	t.Setenv("TEST_EXOSCALE_CREDENTIAL", "alternate-env-fixture")
	cfg, err := resolveConfig(t.Context(), wrapping.WithKeyId(testkms.KeyID),
		wrapping.WithConfigMap(map[string]string{"zone": testkms.Zone,
			"api_key": "env://TEST_EXOSCALE_CREDENTIAL", "api_secret": "env://TEST_EXOSCALE_CREDENTIAL"}))
	if err != nil || cfg["api_secret"] != "alternate-env-fixture" {
		t.Fatal("alternate environment credential was not resolved")
	}
}

func TestPluginRejectsUntrustedTLS(t *testing.T) {
	var requests atomic.Int32
	cfg, endpoint := fakeEndpoint(t, func(http.ResponseWriter, *http.Request, string) bool {
		requests.Add(1)
		return false
	})
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
	w := pluginClient(t, "TestServer")
	if err := configureRemote(t.Context(), w, cfg.KeyID, endpoint); err == nil || requests.Load() != 0 {
		t.Fatal("untrusted peer reached the KMS HTTP handler")
	}
}

func TestPluginRejectsInvalidEnvelopeBeforeKMS(t *testing.T) {
	var requests atomic.Int32
	cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, _ *http.Request, op string) bool {
		if op == "decrypt" {
			requests.Add(1)
		}
		return false
	})
	w := pluginClient(t, "TestServer")
	if err := configureRemote(t.Context(), w, cfg.KeyID, endpoint); err != nil {
		t.Fatal("configure envelope probe:", err)
	}
	for _, key := range []*wrapping.KeyInfo{
		nil, {KeyId: "invalid/path", WrappedKey: []byte{1}}, {KeyId: testkms.KeyID},
	} {
		if _, err := w.Decrypt(t.Context(), &wrapping.BlobInfo{KeyInfo: key}); err == nil ||
			!strings.Contains(err.Error(), "invalid Exoscale KMS envelope key information") || requests.Load() != 0 {
			t.Fatal("invalid envelope was not rejected locally")
		}
	}
}
