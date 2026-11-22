// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	upstream "github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2"
	"google.golang.org/protobuf/proto"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

var liveSealPayload = []byte("live synthetic seal fixture")

func TestLiveConformance(t *testing.T) {
	// The plugin's historical zone variable takes priority for this command.
	if zone := os.Getenv(upstream.EnvExoscaleKmsZone); zone != "" {
		t.Setenv("EXOSCALE_ZONE", zone)
	}
	cfg := conformance.LiveConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	settings := map[string]string{"key_id": cfg.KeyID, "zone": cfg.Zone}
	if endpoint := os.Getenv(upstream.EnvExoscaleKmsEndpoint); endpoint != "" {
		settings["endpoint"] = endpoint
	}
	for _, setting := range []struct{ field, env string }{
		{"api_key", "EXOSCALEKMS_API_KEY_FILE"}, {"api_secret", "EXOSCALEKMS_API_SECRET_FILE"},
	} {
		if path := os.Getenv(setting.env); path != "" {
			settings[setting.field] = "file://" + path
		}
	}
	origin := pluginClient(t, "TestServer")
	setLiveConfig(t, ctx, origin, settings)
	blob, old, encryptTime := initialSeal(t, ctx, origin)
	if !t.Run("plugin_roundtrip", func(t *testing.T) {
		keyLen := len(blob.GetKeyInfo().GetWrappedKey())
		start := time.Now()
		liveDecrypt(t, ctx, origin, old)
		t.Logf("KMS plugin_roundtrip encrypt_ms=%d decrypt_ms=%d blob_bytes=%d wrapped_bytes=%d", encryptTime.Milliseconds(), time.Since(start).Milliseconds(), len(old), keyLen)
	}) {
		return
	}
	t.Run("bare_wrapper", func(t *testing.T) {
		bare := upstream.NewWrapper()
		effective, err := resolveConfig(ctx, wrapping.WithConfigMap(settings))
		if err != nil {
			t.Fatal("resolve effective live plugin settings")
		}
		if _, err := bare.SetConfig(ctx, wrapping.WithConfigMap(effective), wrapping.WithDisallowEnvVars(true)); err != nil {
			t.Fatal("configure bare upstream wrapper")
		}
		liveDecrypt(t, ctx, bare, old)
		t.Log("KMS bare_wrapper plugin_blob_decrypt=true")
	})
	t.Run("refused_credential", func(t *testing.T) {
		t.Setenv(upstream.EnvExoscaleApiSecret, cfg.APISecret+"-conformance-invalid")
		w := pluginClient(t, "TestServer")
		_, err := w.SetConfig(ctx, wrapping.WithConfigMap(settings))
		if err == nil || !strings.Contains(err.Error(), "HTTP 403 (unclassified)") {
			t.Fatal("plugin configuration must report HTTP 403 with a safe problem label")
		}
		t.Log("KMS plugin_refused_credential status=403 type=unclassified")
	})
	t.Run("unknown_key", func(t *testing.T) {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal("generate unknown key UUID")
		}
		nonce[6], nonce[8] = nonce[6]&15|64, nonce[8]&63|128
		unknown := fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
		t.Setenv(upstream.EnvExoscaleKmsKeyId, unknown)
		unknownSettings := map[string]string{"key_id": unknown}
		for field, value := range settings {
			if field != "key_id" {
				unknownSettings[field] = value
			}
		}
		w := pluginClient(t, "TestServer")
		_, err := w.SetConfig(ctx, wrapping.WithConfigMap(unknownSettings))
		if err == nil || !strings.Contains(err.Error(), "configure: HTTP 400 (#/kms-key/not-found)") {
			t.Fatal("plugin configuration must report HTTP 400 with the exact unknown-key type")
		}
	})
	zone := os.Getenv("EXOSCALEKMS_LIVE_REPLICA_ZONE")
	if zone != "" {
		if zone == cfg.Zone || !kmsapi.ValidZone(zone) {
			t.Fatal("replica must be a different valid zone")
		}
		t.Run("plugin_replica", func(t *testing.T) {
			t.Setenv(upstream.EnvExoscaleKmsEndpoint, "")
			t.Setenv(upstream.EnvExoscaleKmsZone, zone)
			remote := pluginClient(t, "TestServer")
			setLiveConfig(t, ctx, remote, map[string]string{
				"key_id": cfg.KeyID, "zone": zone, "api_key": settings["api_key"], "api_secret": settings["api_secret"],
			})
			liveDecrypt(t, ctx, remote, old)
			liveDecrypt(t, ctx, origin, liveWire(t, ctx, remote))
			t.Log("KMS plugin_replica same_uuid=true both_directions=true")
		})
	}
	if os.Getenv("EXOSCALEKMS_LIVE_ROTATE") == "1" && !t.Failed() {
		t.Run("rotation", func(t *testing.T) { liveRotation(t, ctx, cfg, settings, zone) })
	}
}

func liveRotation(t *testing.T, ctx context.Context, cfg kmsapi.Config, settings map[string]string, zone string) {
	t.Helper()
	if deadline, ok := t.Deadline(); ok && time.Until(deadline) < 3*time.Minute {
		t.Fatal("rotation probe needs at least three minutes before the test deadline")
	}
	raw := conformance.LiveClient(t, cfg)
	effective, err := resolveConfig(ctx, wrapping.WithConfigMap(settings))
	if err != nil || effective["endpoint"] != raw.Endpoint || strings.ToLower(effective["key_id"]) != cfg.KeyID {
		t.Fatal("rotation requires the default origin zone endpoint")
	}
	var replica conformance.Client
	if zone != "" {
		replicaCfg := cfg
		replicaCfg.Zone = zone
		replica = conformance.LiveClient(t, replicaCfg)
		replica.Unanswered = raw.Unanswered
	}
	liveRotationProbe(ctx, cfg, settings, zone, raw.Endpoint, raw, replica).Run(t)
}

// liveRotationProbe is the single wiring of the live rotation switch: the
// manual limit without a replica zone, the replica lifecycle with one, and the
// plugin blobs on the created key in both cases. TestPluginRotationUsesDisposableKey
// runs this wiring against the fake, with a loopback plugin endpoint.
func liveRotationProbe(ctx context.Context, cfg kmsapi.Config, settings map[string]string, zone, pluginEndpoint string, origin, replica conformance.Client) conformance.RotationProbe {
	p := conformance.RotationProbe{Origin: origin, ConfiguredKey: cfg.KeyID, ReplicaZone: zone, CheckLimit: zone == ""}
	if zone != "" {
		p.Replica = replica
	}
	p.BeforeSeal = func(t *testing.T, id string, version int) func(*testing.T, int) {
		return configureRotationSeal(t, ctx, id, cfg.Zone, pluginEndpoint, settings, version)
	}
	return p
}

func configureRotationSeal(t *testing.T, ctx context.Context, id, zone, endpoint string, settings map[string]string, version int) func(*testing.T, int) {
	t.Helper()
	// The plugin's historical environment override would otherwise select
	// the configured key instead of the UUID returned by create.
	t.Setenv(upstream.EnvExoscaleKmsKeyId, id)
	w := pluginClient(t, "TestServer")
	owned := map[string]string{"key_id": id, "zone": zone, "endpoint": endpoint,
		"api_key": settings["api_key"], "api_secret": settings["api_secret"]}
	setLiveConfig(t, ctx, w, owned)
	return rotationSeal(t, ctx, w, version)
}

func rotationSeal(t *testing.T, ctx context.Context, w wrapping.Wrapper, before int) func(*testing.T, int) {
	t.Helper()
	old := versionedPluginWire(t, ctx, w, "rotation_old_seal", before)
	return func(t *testing.T, after int) {
		fresh := versionedPluginWire(t, ctx, w, "rotation_fresh_seal", after)
		liveDecrypt(t, ctx, w, old)
		liveDecrypt(t, ctx, w, fresh)
		t.Log("KMS plugin_blobs_after_rotation old_decrypt=true new_decrypt=true")
	}
}

func versionedPluginWire(t *testing.T, ctx context.Context, w wrapping.Wrapper, label string, version int) []byte {
	t.Helper()
	blob, wire := marshalSeal(t, ctx, w)
	keyLen := len(blob.GetKeyInfo().GetWrappedKey())
	overhead := conformance.MeasuredOverhead(version)
	if overhead == 0 || keyLen != 32+overhead || len(wire) != keyLen+103 {
		t.Errorf("%s: live plugin blob or wrapped key length differs from the material version", label)
	}
	return wire
}

func setLiveConfig(t *testing.T, ctx context.Context, w wrapping.Wrapper, config map[string]string) {
	t.Helper()
	if _, err := w.SetConfig(ctx, wrapping.WithConfigMap(config)); err != nil {
		t.Fatal("configure live plugin:", err)
	}
}

func liveEncrypt(t *testing.T, ctx context.Context, w wrapping.Wrapper) *wrapping.BlobInfo {
	t.Helper()
	blob, err := w.Encrypt(ctx, liveSealPayload)
	if err != nil || blob == nil {
		t.Fatal("encrypt live seal fixture")
	}
	return blob
}

func liveWire(t *testing.T, ctx context.Context, w wrapping.Wrapper) []byte {
	t.Helper()
	_, wire := sealFixture(t, ctx, w)
	return wire
}

// initialSeal seals the first fixture of the live suite through the measured
// length check; the offline skew test calls it directly.
func initialSeal(t *testing.T, ctx context.Context, w wrapping.Wrapper) (*wrapping.BlobInfo, []byte, time.Duration) {
	t.Helper()
	start := time.Now()
	blob, wire := sealFixture(t, ctx, w)
	return blob, wire, time.Since(start)
}

// sealFixture encrypts the fixture and checks the measured lengths; every live
// seal blob, including the first one, goes through it.
func sealFixture(t *testing.T, ctx context.Context, w wrapping.Wrapper) (*wrapping.BlobInfo, []byte) {
	t.Helper()
	blob, wire := marshalSeal(t, ctx, w)
	checkSealLengths(t, len(wire), len(blob.GetKeyInfo().GetWrappedKey()))
	return blob, wire
}

func marshalSeal(t *testing.T, ctx context.Context, w wrapping.Wrapper) (*wrapping.BlobInfo, []byte) {
	t.Helper()
	blob := liveEncrypt(t, ctx, w)
	wire, err := proto.Marshal(blob)
	if err != nil {
		t.Fatal("marshal live seal blob")
	}
	return blob, wire
}

// These seal checks read no key metadata, and the replica can emit the
// previous version after rotation. Accept the 223- and 224-byte wraps of the
// measured 191- and 192-byte overheads, as every version-unaware check does;
// the unexplained 222-byte sample of v0.1.0 is not accepted. The fixture
// protobuf fields contribute 103 bytes.
func checkSealLengths(t *testing.T, blobLen, keyLen int) {
	t.Helper()
	if !measuredSealLengths(blobLen, keyLen) {
		t.Fatal("live plugin blob or wrapped key length differs from the measurement")
	}
}

func measuredSealLengths(blobLen, keyLen int) bool {
	return conformance.MeasuredCiphertextLength(32, keyLen) && blobLen == keyLen+103
}

func liveDecrypt(t *testing.T, ctx context.Context, w wrapping.Wrapper, wire []byte) {
	t.Helper()
	var blob wrapping.BlobInfo
	if proto.Unmarshal(wire, &blob) != nil {
		t.Fatal("decode live seal blob")
	}
	got, err := w.Decrypt(ctx, &blob)
	defer clear(got)
	if err != nil || !bytes.Equal(got, liveSealPayload) {
		t.Fatal("live plugin decrypt did not recover the fixture")
	}
}
