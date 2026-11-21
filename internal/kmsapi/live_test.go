// SPDX-License-Identifier: MPL-2.0

package kmsapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func TestLiveAPIConformance(t *testing.T) {
	if os.Getenv("EXOSCALEKMS_LIVE") != "1" || os.Getenv("EXOSCALEKMS_KEY_ID") == "" ||
		!credentialPresent("EXOSCALE_API_KEY", "EXOSCALEKMS_API_KEY_FILE") ||
		!credentialPresent("EXOSCALE_API_SECRET", "EXOSCALEKMS_API_SECRET_FILE") {
		t.Skip("requires explicit live opt-in, a KMS key ID and Exoscale credentials")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cfg, err := kmsapi.Resolve(ctx, nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	origin := liveClient(t, ctx, cfg)
	if os.Getenv("EXOSCALEKMS_LIVE_LEAST_PRIVILEGE") == "1" {
		checkSealRole(t, ctx, origin, cfg)
		return
	}
	old := makeSamples(t, ctx, origin, cfg.KeyID)
	checkSamples(t, ctx, origin, cfg.KeyID, old)
	t.Logf("decoded wrapped sizes: encrypt=%d generate-data-key=%d; UTF-8: encrypt=%t generate-data-key=%t",
		len(old.wrapped), len(old.generated), utf8.Valid(old.wrapped), utf8.Valid(old.generated))

	if zone := os.Getenv("EXOSCALEKMS_LIVE_REPLICA_ZONE"); zone != "" {
		replicaCheck(t, ctx, origin, cfg, zone, old)

	} else {
		t.Log("replica unmeasured: set EXOSCALEKMS_LIVE_REPLICA_ZONE to a ready replica zone")
	}
	probeRemoteErrors(t, ctx, origin, cfg, old.wrapped)
	probeSizes(t, ctx, origin, cfg.KeyID)
	if os.Getenv("EXOSCALEKMS_LIVE_RATE_PROBE") == "1" {
		probeRate(t, ctx, origin, cfg.KeyID, old.wrapped)
	} else {
		t.Log("rate unmeasured: set EXOSCALEKMS_LIVE_RATE_PROBE=1 for the bounded decrypt probe")
	}
}

func credentialPresent(value, file string) bool {
	return os.Getenv(value) != "" || os.Getenv(file) != ""
}

func liveClient(t *testing.T, ctx context.Context, cfg kmsapi.Config) *kmsapi.Client {
	t.Helper()
	c, err := kmsapi.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type samples struct {
	raw, wrapped       []byte
	dataKey, generated []byte
}

func makeSamples(t *testing.T, ctx context.Context, c *kmsapi.Client, id string) samples {
	t.Helper()
	raw := make([]byte, kmsapi.KeySize)
	t.Cleanup(func() { clear(raw) })
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("generate conformance fixture")
	}
	wrapped, err := c.Encrypt(ctx, id, raw)
	if err != nil {
		t.Fatal(err)
	}
	key, generated, err := c.GenerateDataKey(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key) })
	return samples{raw, wrapped, key, generated}
}

func checkSamples(t *testing.T, ctx context.Context, c *kmsapi.Client, id string, s samples) {
	t.Helper()
	for _, v := range []struct{ raw, wrapped []byte }{{s.raw, s.wrapped}, {s.dataKey, s.generated}} {
		got, err := c.Decrypt(ctx, id, v.wrapped)
		match := bytes.Equal(got, v.raw)
		clear(got)
		if err != nil || !match {
			t.Fatalf("opaque KMS ciphertext did not decrypt to its original key: %v", err)
		}
	}
}

func replicaCheck(t *testing.T, ctx context.Context, origin *kmsapi.Client, cfg kmsapi.Config, zone string, old samples) {
	t.Helper()
	if zone == cfg.Zone {
		t.Fatal("replica probe requires a different zone")
	}
	cfg.Zone = zone
	replica := liveClient(t, ctx, cfg)
	checkSamples(t, ctx, replica, cfg.KeyID, old)
	other := makeSamples(t, ctx, replica, cfg.KeyID)
	checkSamples(t, ctx, origin, cfg.KeyID, other)
	t.Log("same-UUID replica and origin both decrypted ciphertexts written in the other zone")
}

func probeSizes(t *testing.T, ctx context.Context, c *kmsapi.Client, id string) {
	t.Helper()
	largest := 0
	for size := kmsapi.KeySize; size <= 16<<10; size *= 2 {
		err := checkSize(ctx, c, id, size)
		if err != nil {
			var status *kmsapi.StatusError
			if !errors.As(err, &status) || (status.Code != 400 && status.Code != 413 && status.Code != 422) {
				t.Fatal(err)
			}
			t.Logf("payload probe: largest tested round trip %d bytes; HTTP %d at %d bytes", largest, status.Code, size)
			return
		}
		largest = size
	}
	t.Logf("payload probe: round trip through %d bytes; upper bound unmeasured", largest)
}

func checkSize(ctx context.Context, c *kmsapi.Client, id string, size int) error {
	input := make([]byte, size)
	defer clear(input)
	if _, err := rand.Read(input); err != nil {
		return errors.New("generate size-probe fixture")
	}
	wrapped, err := c.Encrypt(ctx, id, input)
	if err != nil {
		return err
	}
	got, err := c.Decrypt(ctx, id, wrapped)
	defer clear(got)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, input) {
		return errors.New("size probe round-trip mismatch")
	}
	return nil
}

func probeRate(t *testing.T, ctx context.Context, c *kmsapi.Client, id string, wrapped []byte) {
	t.Helper()
	body, err := json.Marshal(struct {
		Ciphertext []byte `json:"ciphertext"`
	}{wrapped})
	if err != nil {
		t.Fatal("encode rate-probe request")
	}
	start := time.Now()
	pacer := time.NewTicker(125 * time.Millisecond)
	defer pacer.Stop()
	for i := 0; i < 32; i++ {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-pacer.C:
		}
		err := kmsapi.ProbeOnce(ctx, c, id, "decrypt", body)
		var status *kmsapi.StatusError
		if errors.As(err, &status) && status.Code == http.StatusTooManyRequests {
			t.Logf("first HTTP 429 after %d successful requests in %s", i, time.Since(start))
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("no HTTP 429 at 32 paced requests in %s; service quota unmeasured", time.Since(start))
}

func checkSealRole(t *testing.T, ctx context.Context, c *kmsapi.Client, cfg kmsapi.Config) {
	t.Helper()
	raw := make([]byte, kmsapi.KeySize)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("generate IAM probe fixture")
	}
	wrapped, err := c.Encrypt(ctx, cfg.KeyID, raw)
	requireStatus(t, "seal encrypt", err, http.StatusOK)
	got, err := c.Decrypt(ctx, cfg.KeyID, wrapped)
	requireStatus(t, "seal decrypt", err, http.StatusOK)
	match := bytes.Equal(got, raw)
	clear(got)
	if !match {
		t.Fatal("seal role decrypt did not recover fixture")
	}
	got, _, err = c.GenerateDataKey(ctx, cfg.KeyID)
	clear(got)
	requireStatus(t, "seal generate-data-key", err, http.StatusForbidden)
	probeUnknownKey(t, ctx, c, wrapped)
	if other := os.Getenv("EXOSCALEKMS_LIVE_OTHER_KEY_ID"); other != "" {
		if other == cfg.KeyID {
			t.Fatal("other-KMS-key probe requires a distinct enabled test key")
		}
		_, err := c.Encrypt(ctx, other, raw)
		requireStatus(t, "seal encrypt for a different key", err, http.StatusForbidden)
	}

	// Lifecycle probes can succeed against an over-broad role. These run only
	// with separate opt-in and only against the disposable active probe key.
	if os.Getenv("EXOSCALEKMS_LIVE_DISPOSABLE") == "1" {
		t.Run("lifecycle denial", func(t *testing.T) {
			t.Run("schedule deletion", func(t *testing.T) {
				requireStatus(t, "seal schedule-deletion",
					kmsapi.ProbeOnce(ctx, c, cfg.KeyID, "schedule-deletion", []byte(`{"delay-days":7}`)),
					http.StatusForbidden)
			})
			if t.Failed() {
				t.Fatal("stop lifecycle probes and have a key administrator check the disposable key")
			}
			requireStatus(t, "seal disable",
				kmsapi.ProbeOnce(ctx, c, cfg.KeyID, "disable", nil), http.StatusForbidden)
		})
	} else {
		t.Log("lifecycle IAM denial unmeasured; set EXOSCALEKMS_LIVE_DISPOSABLE=1 only on a disposable key")
	}
}

func probeUnknownKey(t *testing.T, ctx context.Context, c *kmsapi.Client, wrapped []byte) {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal("generate unknown key UUID")
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	unknown := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	got, err := c.Decrypt(ctx, unknown, wrapped)
	clear(got)
	requireStatus(t, "unknown key decrypt", err, http.StatusForbidden, http.StatusBadRequest)
}

func probeRemoteErrors(t *testing.T, ctx context.Context, c *kmsapi.Client, cfg kmsapi.Config, wrapped []byte) {
	t.Helper()
	probeUnknownKey(t, ctx, c, wrapped)
	if disabled := os.Getenv("EXOSCALEKMS_LIVE_DISABLED_KEY_ID"); disabled != "" {
		_, err := c.Encrypt(ctx, disabled, make([]byte, kmsapi.KeySize))
		requireStatus(t, "disabled key encrypt", err, http.StatusBadRequest)
	} else {
		t.Log("disabled key unmeasured; set EXOSCALEKMS_LIVE_DISABLED_KEY_ID to a disabled test key")
	}
	var wrong [32]byte
	if _, err := rand.Read(wrong[:]); err != nil {
		t.Fatal("generate refused-credential fixture")
	}
	cfg.APISecret = fmt.Sprintf("%x", wrong[:])
	clear(wrong[:])
	bad := liveClient(t, ctx, cfg)
	got, err := bad.Decrypt(ctx, cfg.KeyID, wrapped)
	clear(got)
	requireStatus(t, "wrong secret decrypt", err, http.StatusUnauthorized, http.StatusForbidden)
}

func requireStatus(t *testing.T, probe string, err error, want ...int) {
	t.Helper()
	code := http.StatusOK
	if err != nil {
		var status *kmsapi.StatusError
		if !errors.As(err, &status) {
			t.Fatalf("%s: could not establish HTTP status: %v", probe, err)
		}
		code = status.Code
	}
	reason := ""
	var status *kmsapi.StatusError
	if errors.As(err, &status) {
		reason = status.Reason
	}
	t.Logf("%s: HTTP %d, approved reason %q", probe, code, reason)
	if !slices.Contains(want, code) {
		t.Fatalf("%s: expected HTTP status in %v", probe, want)
	}
}
