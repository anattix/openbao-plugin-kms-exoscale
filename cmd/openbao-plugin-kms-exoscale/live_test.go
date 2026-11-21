// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"
	"time"
	"unicode/utf8"

	exoscale "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	upstream "github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2"
	"google.golang.org/protobuf/proto"
)

func TestLiveConformance(t *testing.T) {
	if os.Getenv("EXOSCALEKMS_LIVE") != "1" || os.Getenv(upstream.EnvExoscaleKmsKeyId) == "" ||
		!liveCredential(upstream.EnvExoscaleApiKey, "EXOSCALEKMS_API_KEY_FILE") ||
		!liveCredential(upstream.EnvExoscaleApiSecret, "EXOSCALEKMS_API_SECRET_FILE") {
		t.Skip("requires live opt-in, Exoscale credentials and a KMS key ID")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	config := map[string]string{
		"zone":       os.Getenv(upstream.EnvExoscaleKmsZone),
		"key_id":     os.Getenv(upstream.EnvExoscaleKmsKeyId),
		"endpoint":   os.Getenv(upstream.EnvExoscaleKmsEndpoint),
		"api_key":    "file://" + os.Getenv("EXOSCALEKMS_API_KEY_FILE"),
		"api_secret": "file://" + os.Getenv("EXOSCALEKMS_API_SECRET_FILE"),
	}
	w := pluginClient(t, "TestServer")
	setLiveConfig(t, ctx, w, config)
	payload := []byte("live synthetic seal fixture")
	old := liveEncrypt(t, ctx, w, payload)
	liveDecrypt(t, ctx, w, old, payload)
	probeLiveReplica(t, ctx, w, config, old, payload)
	if os.Getenv("EXOSCALEKMS_LIVE_ROTATE") == "1" {
		rotateLiveKey(t, ctx, config)
		liveDecrypt(t, ctx, w, old, payload)
		liveDecrypt(t, ctx, w, liveEncrypt(t, ctx, w, payload), payload)
		t.Log("old and fresh plugin blobs decrypted after rotation")
	} else {
		t.Log("rotation unmeasured; requires opt-in and a disposable key")
	}
}

func liveCredential(value, file string) bool {
	return os.Getenv(value) != "" || os.Getenv(file) != ""
}

func setLiveConfig(t *testing.T, ctx context.Context, w wrapping.Wrapper, config map[string]string) {
	t.Helper()
	if _, err := w.SetConfig(ctx, wrapping.WithConfigMap(config)); err != nil {
		t.Fatal("configure live plugin:", err)
	}
}

func liveEncrypt(t *testing.T, ctx context.Context, w wrapping.Wrapper, payload []byte) []byte {
	t.Helper()
	start := time.Now()
	blob, err := w.Encrypt(ctx, payload)
	if err != nil {
		t.Fatal("live plugin encrypt:", err)
	}
	wire, err := proto.Marshal(blob)
	if err != nil {
		t.Fatal("serialize live plugin blob")
	}
	wrapped := blob.GetKeyInfo().GetWrappedKey()
	t.Logf("plugin encrypt and serialization elapsed %s, blob %d bytes, wrapped key %d bytes (UTF-8: %t)", time.Since(start), len(wire), len(wrapped), utf8.Valid(wrapped))
	return wire
}

func liveDecrypt(t *testing.T, ctx context.Context, w wrapping.Wrapper, wire, payload []byte) {
	t.Helper()
	var blob wrapping.BlobInfo
	if proto.Unmarshal(wire, &blob) != nil {
		t.Fatal("decode live plugin blob")
	}
	start := time.Now()
	got, err := w.Decrypt(ctx, &blob)
	defer clear(got)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("live plugin decrypt did not recover the fixture:", err)
	}
	t.Logf("plugin decrypt elapsed %s", time.Since(start))
}

func probeLiveReplica(t *testing.T, ctx context.Context, origin wrapping.Wrapper, config map[string]string, old, payload []byte) {
	t.Helper()
	zone := os.Getenv("EXOSCALEKMS_LIVE_REPLICA_ZONE")
	if zone == "" {
		t.Log("replica unmeasured; requires an existing synchronized replica")
		return
	}
	settings, err := resolveConfig(ctx, wrapping.WithConfigMap(config))
	if err != nil {
		t.Fatal("resolve replica probe settings:", err)
	}
	// Start a child with environment overrides only for its destination.
	t.Setenv(upstream.EnvExoscaleKmsEndpoint, "")
	t.Setenv(upstream.EnvExoscaleKmsZone, zone)
	remote := pluginClient(t, "TestServer")
	setLiveConfig(t, ctx, remote, map[string]string{
		"key_id": settings["key_id"], "api_key": config["api_key"], "api_secret": config["api_secret"],
	})
	liveDecrypt(t, ctx, remote, old, payload)
	liveDecrypt(t, ctx, origin, liveEncrypt(t, ctx, remote, payload), payload)
	// Restore the origin configuration for subsequent probes.
	t.Setenv(upstream.EnvExoscaleKmsEndpoint, config["endpoint"])
	t.Setenv(upstream.EnvExoscaleKmsZone, config["zone"])
	t.Log("origin and replica decrypted each other's plugin blobs")
}

func rotateLiveKey(t *testing.T, ctx context.Context, config map[string]string) {
	t.Helper()
	settings, err := resolveConfig(ctx, wrapping.WithConfigMap(config))
	if err != nil {
		t.Fatal("resolve rotation probe settings:", err)
	}
	// Disable vendor retries for the lifecycle operation. A lost reply must
	// never cause an automatic second rotation.
	client, err := exoscale.NewClient(credentials.NewStaticCredentials(settings["api_key"], settings["api_secret"]),
		exoscale.ClientOptWithEndpoint(exoscale.Endpoint(settings["endpoint"])),
		exoscale.ClientOptWithHTTPClient(&http.Client{CheckRedirect: noRedirect}))
	if err != nil {
		t.Fatal("initialize rotation probe")
	}
	op, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := client.RotateKmsKey(op, exoscale.UUID(settings["key_id"])); err != nil {
		t.Fatal(publicError(op, "rotate disposable key", err))
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
