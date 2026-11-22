// SPDX-License-Identifier: MPL-2.0

package kmsapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	const id = "aaaaaaaa-1111-4111-8111-111111111111"
	t.Setenv("EXOSCALEKMS_KEY_ID", id)
	t.Setenv("EXOSCALE_ZONE", "ch-dk-2")
	t.Setenv("EXOSCALEKMS_API_KEY_FILE", "")
	t.Setenv("EXOSCALE_API_KEY", "unit-fixture")
	t.Setenv("EXOSCALEKMS_TIMEOUT", "2s")
	fixture := filepath.Join(t.TempDir(), "identifier")
	if err := os.WriteFile(fixture, []byte("file-fixture\n"), 0600); err != nil {
		t.Fatal("create test configuration")
	}
	for _, tc := range []struct {
		name               string
		settings           map[string]string
		id                 string
		disallow           bool
		zone, api, timeout string
		ok                 bool
	}{
		{"environment", nil, "", false, "ch-dk-2", "unit-fixture", "2s", true},
		{"explicit takes priority", map[string]string{"key_id": "invalid", "zone": "ch-gva-2", "api_key_file": fixture}, id, false, "ch-gva-2", "file-fixture", "2s", true},
		{"disable environment", map[string]string{"zone": "ch-gva-2"}, id, true, "ch-gva-2", "", "3s", true},
		{"missing settings", nil, "", true, "", "", "", false},
		{"invalid timeout", map[string]string{"timeout": "20s"}, "", false, "", "", "", false},
		{"invalid zone", map[string]string{"zone": "../../example"}, "", false, "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Resolve(t.Context(), tc.settings, tc.id, tc.disallow)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected configuration result: %v", err)
			}
			if tc.ok && (cfg.KeyID != id || cfg.Zone != tc.zone || cfg.APIKey != tc.api || cfg.Timeout.String() != tc.timeout) {
				t.Fatal("configuration did not honor precedence")
			}
		})
	}
}

func TestResolveAllowedKeyIDs(t *testing.T) {
	const active = "aaaaaaaa-1111-4111-8111-111111111111"
	const older = "bbbbbbbb-2222-4222-8222-222222222222"
	t.Setenv("EXOSCALEKMS_ALLOWED_KEY_IDS", older)
	for _, tc := range []struct {
		name, setting, legacy  string
		useEnv, allowed, valid bool
	}{
		{"allowlisted environment key", "", "", true, true, true},
		{"explicit empty list takes precedence", "", "", false, false, true},
		{"explicit list normalizes UUID", "  BBBBBBBB-2222-4222-8222-222222222222  ", "", false, true, true},
		{"invalid list", older + ",invalid", "", false, false, false},
		{"legacy wildcard rejected", "", "true", false, false, false},
		{"legacy false keeps default", "", "false", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]string{"zone": "ch-dk-2", "allow_other_keys": tc.legacy}
			if !tc.useEnv {
				settings["allowed_key_ids"] = tc.setting
			}
			cfg, err := Resolve(t.Context(), settings, active, false)
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected configuration result: %v", err)
			}
			if !tc.valid {
				return
			}
			id, err := ResolveDecryptionKey(cfg.KeyID, older, cfg.AllowedKeyIDs)
			if (err == nil) != tc.allowed || (tc.allowed && id != older) {
				t.Fatal("historical key policy did not match the configured UUID list")
			}
		})
	}
}

func TestReadExactCredentialFile(t *testing.T) {
	for _, tc := range []struct {
		name, contents string
		wantError      string
	}{
		{name: "exact", contents: "fixture"},
		{name: "at limit", contents: strings.Repeat("x", 8192)},
		{name: "over limit", contents: strings.Repeat("x", 8193), wantError: "cannot read or validate"},
		{name: "empty", wantError: "must be nonempty"},
		{name: "leading space", contents: " fixture", wantError: "no surrounding whitespace"},
		{name: "trailing newline", contents: "fixture\n", wantError: "no surrounding whitespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture")
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatal("write credential fixture")
			}
			got, err := ReadExactCredentialFile(t.Context(), path)
			if tc.wantError != "" {
				if got != "" || err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatal("expected a bounded, sanitized credential-file error")
				}
			} else if err != nil || got != tc.contents {
				t.Fatal("valid credential file did not preserve its exact contents")
			}
		})
	}
}

func TestEncryptionContextValidation(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		invalid     bool
	}{
		{name: "unset"},
		{name: "1024 bytes", value: strings.Repeat("é", 512)},
		{name: "1025 bytes", value: strings.Repeat("é", 512) + "x", invalid: true},
		{name: "invalid UTF-8", value: "\xff", invalid: true},
		{name: "NUL", value: "stack\x00name", invalid: true},
		{name: "terminal control", value: "stack\u007fname", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]string{"zone": "ch-gva-2", "encryption_context": tc.value}
			const id = "44444444-4444-4444-8444-444444444444"
			cfg, err := Resolve(t.Context(), settings, id, true)
			const invalid = "EXOSCALEKMS_ENCRYPTION_CONTEXT must be at most 1024 bytes of printable UTF-8"
			if tc.invalid {
				if err == nil || err.Error() != invalid {
					t.Fatal("expected safe encryption context validation error")
				}
			} else if err != nil || cfg.EncryptionContext != tc.value {
				t.Fatal("valid context changed or was rejected")
			}
		})
	}
}
