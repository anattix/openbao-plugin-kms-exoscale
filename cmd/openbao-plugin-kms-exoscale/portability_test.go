// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestStanzaPortability(t *testing.T) {
	for _, tc := range []struct {
		name                                                                    string
		trailingSlash, missingFile, newlineFile, missingEnv, emptyEnv, disallow bool
		pluginOK, bareOK                                                        bool
	}{
		{name: "explicit HTTPS and environment", pluginOK: true, bareOK: true},
		{name: "trailing slash", trailingSlash: true, pluginOK: true, bareOK: true},
		{name: "missing file under environment value", missingFile: true},
		{name: "environment value beside newline file", newlineFile: true, pluginOK: true, bareOK: true},
		{name: "missing environment reference under environment value", missingEnv: true},
		{name: "empty environment reference under environment value", emptyEnv: true, pluginOK: true, bareOK: true},
		{name: "files under disallow env", disallow: true, pluginOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, endpoint := fakeEndpoint(t, nil)
			settings := map[string]string{"key_id": cfg.KeyID, "endpoint": endpoint}
			if tc.trailingSlash {
				settings["endpoint"] += "/"
			}
			if tc.missingFile {
				settings["api_key"] = "file://" + filepath.Join(t.TempDir(), "absent")
			}
			if tc.newlineFile {
				settings["api_key"] = "file://" + writeFixture(t, "key", cfg.APIKey+"\n")
			}
			if tc.missingEnv || tc.emptyEnv {
				const variable = "EXOSCALEKMS_TEST_CREDENTIAL_REFERENCE"
				t.Setenv(variable, "")
				if tc.missingEnv {
					if err := os.Unsetenv(variable); err != nil {
						t.Fatal("unset synthetic credential reference")
					}
				}
				settings["api_key"] = "env://" + variable
			}
			if tc.disallow {
				settings["api_key"] = "file://" + writeFixture(t, "key", cfg.APIKey)
				settings["api_secret"] = "file://" + writeFixture(t, "secret", cfg.APISecret)
			}
			for _, probe := range []struct {
				server string
				ok     bool
			}{
				{"TestServer", tc.pluginOK}, {"TestBareServer", tc.bareOK},
			} {
				client := pluginClient(t, probe.server)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				config, err := client.SetConfig(ctx, wrapping.WithConfigMap(settings), wrapping.WithDisallowEnvVars(tc.disallow))
				cancel()
				if (err == nil) != probe.ok {
					t.Fatalf("%s configuration success: got %t, want %t", probe.server, err == nil, probe.ok)
				}
				if probe.ok && config.GetMetadata()["endpoint"] != endpoint {
					t.Fatalf("%s did not report the canonical endpoint", probe.server)
				}
			}
		})
	}
}

func TestPluginDisallowEnvKeepsValidatedSettings(t *testing.T) {
	cfg, endpoint := fakeEndpoint(t, nil)
	t.Setenv("EXOSCALEKMS_ENDPOINT", "https://127.0.0.1:1/v2")
	t.Setenv("EXOSCALE_API_SECRET", "synthetic-invalid")
	settings := map[string]string{
		"key_id": cfg.KeyID, "endpoint": endpoint,
		"api_key":    "file://" + writeFixture(t, "key", cfg.APIKey),
		"api_secret": "file://" + writeFixture(t, "secret", cfg.APISecret),
	}
	remote := pluginClient(t, "TestServer")
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, err := remote.SetConfig(ctx, wrapping.WithConfigMap(settings), wrapping.WithDisallowEnvVars(true)); err != nil {
		t.Fatal("wrapper did not use validated endpoint and file credentials")
	}
}

func writeFixture(t *testing.T, name, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal("write synthetic credential fixture")
	}
	return path
}

func TestBareServerStartupDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		callerTimeout, lower, upper time.Duration
	}{
		{"wrapper deadline", 37 * time.Second, 28 * time.Second, 34 * time.Second},
		{"earlier caller deadline", 750 * time.Millisecond, 0, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached atomic.Bool
			cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, r *http.Request, op string) bool {
				if op != "get" {
					return false
				}
				reached.Store(true)
				<-r.Context().Done()
				return true
			})
			client := pluginClient(t, "TestBareServer")
			ctx, cancel := context.WithTimeout(t.Context(), tc.callerTimeout)
			defer cancel()
			start := time.Now()
			err := configureRemote(ctx, client, cfg.KeyID, endpoint)
			elapsed := time.Since(start)
			if err == nil || !reached.Load() || elapsed < tc.lower || elapsed >= tc.upper {
				t.Fatalf("bare startup did not hit the expected deadline window, got %s", elapsed)
			}
		})
	}
}
