// SPDX-License-Identifier: MPL-2.0

package kmsapi_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func TestLiveAPIConformance(t *testing.T) {
	// Check retired options before resolving credentials or making any requests.
	if os.Getenv("EXOSCALEKMS_LIVE") == "1" {
		for _, name := range []string{"EXOSCALEKMS_LIVE_OTHER_KEY_ID", "EXOSCALEKMS_LIVE_DISABLED_KEY_ID"} {
			if _, set := os.LookupEnv(name); set {
				t.Fatalf("%s is no longer read; unset it and set EXOSCALEKMS_LIVE_DISPOSABLE=1 to use a disposable key", name)
			}
		}
		if os.Getenv("EXOSCALEKMS_LIVE_DISPOSABLE") == "1" {
			if deadline, ok := t.Deadline(); ok && time.Until(deadline) < 3*time.Minute {
				t.Fatal("disposable probes need at least three minutes before the test deadline; raise -timeout")
			}
		}
	}
	cfg := conformance.LiveConfig(t)
	if os.Getenv("EXOSCALEKMS_LIVE_LEAST_PRIVILEGE") == "1" {
		t.Run("least_privilege", func(t *testing.T) {
			checkSealRole(t, t.Context(), liveClient(t, t.Context(), cfg), cfg)
		})
		return
	}

	origin := conformance.LiveClient(t, cfg)
	conformance.Data(t, origin, cfg.KeyID)
	zone := os.Getenv("EXOSCALEKMS_LIVE_REPLICA_ZONE")
	if zone != "" {
		if zone == cfg.Zone {
			t.Fatal("replica probe requires a different zone")
		}
		t.Run("replica", func(t *testing.T) {
			replicaCfg := cfg
			replicaCfg.Zone = zone
			replica := conformance.LiveClient(t, replicaCfg)
			replica.Unanswered = origin.Unanswered
			conformance.Replica(t, origin, replica, cfg.KeyID)
		})
	}
	if os.Getenv("EXOSCALEKMS_LIVE_DISPOSABLE") == "1" {
		if zone == "" {
			zone = "ch-dk-2"
			if zone == cfg.Zone {
				zone = "ch-gva-2"
			}
		}
		if !kmsapi.ValidZone(zone) {
			t.Fatal("invalid replication probe zone")
		}
		t.Run("disposable", func(t *testing.T) { conformance.Disposable(t, origin, cfg.KeyID, zone) })
	}
	if os.Getenv("EXOSCALEKMS_LIVE_RATE_PROBE") == "1" {
		t.Run("paced_requests", func(t *testing.T) { conformance.Rate(t, origin, cfg.KeyID) })
	}
}

func liveClient(t *testing.T, ctx context.Context, cfg kmsapi.Config) *kmsapi.Client {
	t.Helper()
	c, err := kmsapi.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func checkSealRole(t *testing.T, ctx context.Context, c *kmsapi.Client, cfg kmsapi.Config) {
	t.Helper()
	raw := make([]byte, kmsapi.KeySize)
	wrapped, err := c.Encrypt(ctx, cfg.KeyID, raw)
	if err != nil {
		t.Fatal("seal role must permit encrypt")
	}
	got, err := c.Decrypt(ctx, cfg.KeyID, wrapped)
	defer clear(got)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("seal role must permit decrypt and recover the bytes")
	}
	got, _, err = c.GenerateDataKey(ctx, cfg.KeyID)
	clear(got)
	var status *kmsapi.StatusError
	if !errors.As(err, &status) || status.Code != http.StatusForbidden {
		t.Fatal("seal role must deny generate-data-key with HTTP 403")
	}
	t.Log("KMS seal_least_privilege encrypt=200 decrypt=200 generate=403")
}

func TestLiveRetiredSwitches(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"EXOSCALEKMS_LIVE_OTHER_KEY_ID", "synthetic"},
		{"EXOSCALEKMS_LIVE_DISABLED_KEY_ID", "synthetic"},
		{"EXOSCALEKMS_LIVE_DISABLED_KEY_ID", ""},
	} {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestLiveAPIConformance$")
			// No child can contact a service, even if the validation regresses.
			for _, env := range os.Environ() {
				if !strings.HasPrefix(env, "EXOSCALE") {
					cmd.Env = append(cmd.Env, env)
				}
			}
			cmd.Env = append(cmd.Env, "EXOSCALEKMS_LIVE=1", tc.name+"="+tc.value)
			output, err := cmd.CombinedOutput()
			var failed *exec.ExitError
			if !errors.As(err, &failed) || !bytes.Contains(output, []byte(tc.name+" is no longer read")) {
				t.Fatal("live subprocess did not reject the retired switch")
			}
		})
	}
}

func TestDisposableRequiresTimeForCleanup(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestLiveAPIConformance$", "-test.timeout", "1m")
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "EXOSCALE") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "EXOSCALEKMS_LIVE=1", "EXOSCALEKMS_LIVE_DISPOSABLE=1")
	output, err := cmd.CombinedOutput()
	var failed *exec.ExitError
	if !errors.As(err, &failed) || !bytes.Contains(output, []byte("need at least three minutes")) {
		t.Fatal("short test deadline did not reject the disposable probe before credential resolution")
	}
}
