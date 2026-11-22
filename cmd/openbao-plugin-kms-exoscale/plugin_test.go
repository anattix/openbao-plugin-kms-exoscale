// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/plugin/v2/plugintest"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	upstream "github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

func TestServer(t *testing.T) {
	plugintest.Server(t, serveOptions())
}

func TestBareServer(t *testing.T) {
	plugintest.Server(t, &plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper { return upstream.NewWrapper() },
	})
}

func TestFastServer(t *testing.T) {
	opts := serveOptions()
	factory := opts.WrapperFactoryFunc
	opts.WrapperFactoryFunc = func() wrapping.Wrapper {
		w := factory().(*guardedWrapper)
		w.timeout = 500 * time.Millisecond
		return w
	}
	plugintest.Server(t, opts)
}

func pluginClient(t *testing.T, server string) wrapping.Wrapper {
	t.Helper()
	client := plugintest.Client(t, "^"+server+"$")
	raw, err := client.Dispense("wrapper")
	if err != nil {
		t.Fatal("dispense wrapper from plugin")
	}
	return raw.(wrapping.Wrapper)
}

func fakeEndpoint(t *testing.T, hook testkms.Hook) (kmsapi.Config, string) {
	t.Helper()
	cfg, endpoint := testkms.StartEndpoint(t, hook)
	setFakeEndpointEnv(t, cfg)
	return cfg, endpoint
}

func setFakeEndpointEnv(t *testing.T, cfg kmsapi.Config) {
	t.Helper()
	t.Setenv("SSL_CERT_FILE", cfg.CAFile)
	t.Setenv("EXOSCALE_API_KEY", cfg.APIKey)
	t.Setenv("EXOSCALE_API_SECRET", cfg.APISecret)
	t.Setenv("EXOSCALEKMS_ENDPOINT", "")
	t.Setenv("EXOSCALEKMS_KEY_ID", "")
	t.Setenv("EXOSCALEKMS_ZONE", "")
}

func configureRemote(ctx context.Context, w wrapping.Wrapper, id, endpoint string) error {
	_, err := w.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{"endpoint": endpoint, "key_id": id}))
	return err
}

func TestPluginInterop(t *testing.T) {
	// Each fake generates its own CA. The subprocesses load separate root pools.
	t.Run("first CA", testPluginInterop)
	t.Run("second CA", testPluginInterop)
}

func testPluginInterop(t *testing.T) {
	var getCalls, encryptCalls, decryptCalls atomic.Int32
	cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, _ *http.Request, op string) bool {
		switch op {
		case "get":
			getCalls.Add(1)
		case "encrypt":
			encryptCalls.Add(1)
		case "decrypt":
			decryptCalls.Add(1)
		}
		return false
	})
	remote := pluginClient(t, "TestServer")
	bare := pluginClient(t, "TestBareServer")
	ctx := t.Context()
	for _, w := range []wrapping.Wrapper{remote, bare} {
		if err := configureRemote(ctx, w, cfg.KeyID, endpoint); err != nil {
			t.Fatal("configure Exoscale wrapper:", err)
		}
	}
	if typ, err := remote.Type(ctx); err != nil || typ != upstream.Type {
		t.Fatal("plugin returned an unexpected wrapper type")
	}
	if id, err := remote.KeyId(ctx); err != nil || id != cfg.KeyID {
		t.Fatal("plugin returned an unexpected key ID")
	}
	payload := []byte("synthetic seal fixture")
	aad := wrapping.WithAad([]byte("synthetic authenticated data"))
	for _, pair := range []struct {
		name           string
		writer, reader wrapping.Wrapper
	}{{"plugin to bare", remote, bare}, {"bare to plugin", bare, remote}, {"plugin to plugin", remote, remote}} {
		t.Run(pair.name, func(t *testing.T) {
			blob, err := pair.writer.Encrypt(ctx, payload, aad)
			if err != nil {
				t.Fatal("encrypt fixture:", err)
			}
			wire, err := proto.Marshal(blob)
			if err != nil {
				t.Fatal("serialize envelope")
			}
			assertStoredFields(t, wire, len(payload), cfg.KeyID)
			var decoded wrapping.BlobInfo
			if proto.Unmarshal(wire, &decoded) != nil {
				t.Fatal("parse envelope")
			}
			got, err := pair.reader.Decrypt(ctx, &decoded, aad)
			defer clear(got)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("reader did not recover the fixture from the writer's wire blob")
			}
		})
	}
	if getCalls.Load() != 2 || encryptCalls.Load() != 3 || decryptCalls.Load() != 3 {
		t.Fatal("cross-read must use the fake KMS for each configuration and crypto operation")
	}
}

func assertStoredFields(t *testing.T, wire []byte, payloadSize int, keyID string) {
	t.Helper()
	fields := wireFields(t, wire, 1, 2, 5)
	if len(fields[1]) != payloadSize+16 || len(fields[2]) != 12 {
		t.Fatal("unexpected ciphertext or nonce length")
	}
	key := wireFields(t, fields[5], 3, 5)
	// The measured fake length is a 32-byte DEK plus 191 bytes.
	// Only the wire field layout is shared with the upstream wrapper.
	if string(key[3]) != keyID || len(key[5]) != 223 {
		t.Fatal("key info must contain the UUID and the untouched opaque wrapped key")
	}
}

func wireFields(t *testing.T, wire []byte, required ...protowire.Number) map[protowire.Number][]byte {
	t.Helper()
	fields := make(map[protowire.Number][]byte)
	for len(wire) > 0 {
		n, typ, tagSize := protowire.ConsumeTag(wire)
		if tagSize < 0 || typ != protowire.BytesType {
			t.Fatal("unexpected wire tag")
		}
		value, size := protowire.ConsumeBytes(wire[tagSize:])
		if size < 0 || fields[n] != nil {
			t.Fatal("invalid or repeated wire field")
		}
		fields[n] = value
		wire = wire[tagSize+size:]
	}
	if len(fields) != len(required) {
		t.Fatal("unexpected stored field count")
	}
	for _, n := range required {
		if len(fields[n]) == 0 {
			t.Fatalf("missing required stored field %d", n)
		}
	}
	return fields
}

func TestPluginRemoteErrors(t *testing.T) {
	const marker = "untrusted-response-marker"
	for _, tc := range []struct {
		name, id, op, want string
		reply              func(http.ResponseWriter, *http.Request)
	}{
		{"unknown key", "44444444-4444-4444-8444-444444444444", "get", "configure: HTTP 400 (#/kms-key/not-found)", nil},
		{"disabled key", testkms.DisabledID, "encrypt", "HTTP 400 (#/kms-key/key-disabled)", nil},
		{"refused credential", testkms.KeyID, "get", "HTTP 403 (unclassified)", nil},
		{"remote error redaction", testkms.KeyID, "encrypt", "HTTP 400 (unclassified)", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"message":"`+marker+`","type":"`+marker+`","title":"`+marker+`"}`)
		}},
		{"truncated answer", testkms.KeyID, "encrypt", "request failed or invalid response", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, `{"ciphertext":"`)
		}},
		{"malformed answer", testkms.KeyID, "encrypt", "request failed or invalid response", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"ciphertext":"not base64"}`)
		}},
		{"truncated decrypt answer", testkms.KeyID, "decrypt", "request failed or invalid response", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, `{"plaintext":"`)
		}},
		{"malformed decrypt answer", testkms.KeyID, "decrypt", "request failed or invalid response", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"plaintext":"not base64"}`)
		}},
		{"empty ciphertext", testkms.KeyID, "encrypt", "empty wrapped key", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "{}")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, endpoint := fakeEndpoint(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
				if tc.reply == nil || op != tc.op {
					return false
				}
				tc.reply(w, r)
				return true
			})
			if tc.name == "refused credential" {
				t.Setenv("EXOSCALE_API_SECRET", "synthetic-invalid")
			}
			remote := pluginClient(t, "TestServer")
			err := configureRemote(t.Context(), remote, tc.id, endpoint)
			if tc.op == "encrypt" && err == nil {
				var blob *wrapping.BlobInfo
				blob, err = remote.Encrypt(t.Context(), []byte("test fixture"))
				if blob != nil {
					t.Fatal("failed call returned a blob")
				}
			}
			if tc.op == "decrypt" && err == nil {
				var plaintext []byte
				plaintext, err = remote.Decrypt(t.Context(), &wrapping.BlobInfo{
					KeyInfo: &wrapping.KeyInfo{WrappedKey: []byte{1}},
				})
				defer clear(plaintext)
				if len(plaintext) != 0 {
					t.Fatal("failed call returned plaintext")
				}
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), marker) {
				t.Fatal("expected sanitized failure class:", tc.want)
			}
		})
	}
}

func TestPluginPersistentServerError(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			const marker = "untrusted-response-marker"
			cfg, endpoint := fakeEndpoint(t, func(w http.ResponseWriter, _ *http.Request, op string) bool {
				if op != "encrypt" {
					return false
				}
				http.Error(w, marker, status)
				return true
			})
			remote := pluginClient(t, "TestFastServer")
			if err := configureRemote(t.Context(), remote, cfg.KeyID, endpoint); err != nil {
				t.Fatal("configure retry probe")
			}
			blob, err := remote.Encrypt(t.Context(), []byte("synthetic fixture"))
			// Once the SDK can surface a bounded final refusal, assert its HTTP status.
			if blob != nil || err == nil || !strings.Contains(err.Error(), "deadline exceeded") ||
				strings.Contains(err.Error(), marker) {
				t.Fatal("expected sanitized deadline while the SDK retries the refusal")
			}
		})
	}
}

func TestPluginDeadline(t *testing.T) {
	for _, blocked := range []string{"get", "encrypt", "decrypt"} {
		t.Run(blocked, func(t *testing.T) {
			cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, r *http.Request, op string) bool {
				if op != blocked {
					return false
				}
				<-r.Context().Done()
				return true
			})
			remote := pluginClient(t, "TestFastServer")
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			start := time.Now()
			err := configureRemote(ctx, remote, cfg.KeyID, endpoint)
			if err == nil && blocked == "encrypt" {
				_, err = remote.Encrypt(ctx, []byte("test fixture"))
			}
			if err == nil && blocked == "decrypt" {
				_, err = remote.Decrypt(ctx, &wrapping.BlobInfo{KeyInfo: &wrapping.KeyInfo{WrappedKey: []byte{1}}})
			}
			if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || time.Since(start) > 3*time.Second {
				t.Fatal("plugin's own operation deadline did not end the stalled request")
			}
		})
	}
}

func TestPluginCancellation(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, r *http.Request, op string) bool {
		if op != "encrypt" {
			return false
		}
		close(started)
		<-r.Context().Done()
		close(ended)
		return true
	})
	remote := pluginClient(t, "TestServer")
	if err := configureRemote(t.Context(), remote, cfg.KeyID, endpoint); err != nil {
		t.Fatal("configure cancellation probe")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := remote.Encrypt(ctx, []byte("test fixture"))
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("KMS did not receive request to cancel")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled request reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("plugin did not return after cancellation")
	}
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not reach the HTTP request")
	}
}

func TestPluginRetriesDroppedConnection(t *testing.T) {
	var attempts atomic.Int32
	cfg, endpoint := fakeEndpoint(t, func(w http.ResponseWriter, _ *http.Request, op string) bool {
		if op != "encrypt" || attempts.Add(1) != 1 {
			return false
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		_ = conn.Close() // Force an EOF before response headers.
		return true
	})
	remote := pluginClient(t, "TestServer")
	if err := configureRemote(t.Context(), remote, cfg.KeyID, endpoint); err != nil {
		t.Fatal("configure retry probe")
	}
	if _, err := remote.Encrypt(t.Context(), []byte("test fixture")); err != nil || attempts.Load() != 2 {
		t.Fatal("plugin failed to recover after one dropped connection")
	}
}

func TestMeasuredSealLengths(t *testing.T) {
	for _, tc := range []struct {
		name          string
		blob, wrapped int
		want          bool
	}{
		{"unexplained historical sample", 325, 222, false},
		{"one digit", 326, 223, true},
		{"two digits", 327, 224, true},
		{"wrong serialization length", 326, 224, false},
		{"unmeasured wrap", 328, 225, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if measuredSealLengths(tc.blob, tc.wrapped) != tc.want {
				t.Fatal("measured seal length check did not match the fixture")
			}
		})
	}
}

func TestPluginSealLengthsAcrossRotation(t *testing.T) {
	cfg, endpoint, rotate := testkms.StartWithRotation(t)
	setFakeEndpointEnv(t, cfg)
	for range 8 {
		rotate()
	}
	ctx := t.Context()
	remote := pluginClient(t, "TestServer")
	if err := configureRemote(ctx, remote, cfg.KeyID, endpoint); err != nil {
		t.Fatal("configure the test plugin")
	}
	old := liveWire(t, ctx, remote)
	if len(old) != 326 {
		t.Fatal("version 9 seal blob must be 326 bytes")
	}
	rotate()
	next := liveWire(t, ctx, remote)
	if len(next) != 327 {
		t.Fatal("version 10 seal blob must be 327 bytes")
	}
	liveDecrypt(t, ctx, remote, old)
	liveDecrypt(t, ctx, remote, next)
}

// TestPluginSealLengthsRejectSkewedOverhead requires the live seal length check
// to reject a valid blob whose wrapped key is two bytes longer than measured.
func TestPluginSealLengthsRejectSkewedOverhead(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_SEAL_SKEW_CHILD"
	if os.Getenv(child) == "1" {
		cfg, endpoint := testkms.StartWithOverheadSkew(t, 2)
		setFakeEndpointEnv(t, cfg)
		remote := pluginClient(t, "TestServer")
		if err := configureRemote(t.Context(), remote, cfg.KeyID, endpoint); err != nil {
			t.Fatal("configure the test plugin")
		}
		t.Run("initial_seal", func(t *testing.T) {
			t.Setenv("EXOSCALEKMS_LIVE", "1")
			t.Setenv("EXOSCALE_ZONE", cfg.Zone)
			t.Setenv(upstream.EnvExoscaleKmsEndpoint, endpoint)
			t.Setenv(upstream.EnvExoscaleKmsKeyId, cfg.KeyID)
			t.Setenv("EXOSCALEKMS_LIVE_REPLICA_ZONE", "")
			t.Setenv("EXOSCALEKMS_LIVE_ROTATE", "")
			TestLiveConformance(t)
		})
		t.Run("live_wire", func(t *testing.T) { liveDecrypt(t, t.Context(), remote, liveWire(t, t.Context(), remote)) })
		t.Run("rotation_seal", func(t *testing.T) {
			after := rotationSeal(t, t.Context(), remote, 1)
			after(t, 2)
		})
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestPluginSealLengthsRejectSkewedOverhead$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || bytes.Count(out, []byte("live plugin blob or wrapped key length differs from the measurement")) != 2 ||
		!bytes.Contains(out, []byte("--- FAIL: TestPluginSealLengthsRejectSkewedOverhead/initial_seal")) ||
		!bytes.Contains(out, []byte("--- FAIL: TestPluginSealLengthsRejectSkewedOverhead/live_wire")) {
		t.Fatal("live seal length check accepted a skewed wrapped key")
	}
	for _, label := range []string{"rotation_old_seal", "rotation_fresh_seal"} {
		if !bytes.Contains(out, []byte(label+": live plugin blob or wrapped key length")) {
			t.Errorf("%s accepted a skewed wrapped key", label)
		}
	}
}

// TestPluginRotationUsesDisposableKey runs the live rotation wiring
// (liveRotationProbe) against the fake, with the configured UUID already in
// env. Raw probe requests use the zone hostnames routed to the loopback fake;
// the plugin uses the loopback endpoint, so the two are counted apart.
func TestPluginRotationUsesDisposableKey(t *testing.T) {
	for _, tc := range []struct {
		name, zone                                      string
		originRotates, replicaRotates, replicaSchedules int
	}{
		{"single_zone", "", 11, 0, 0},
		{"multi_zone", testkms.ReplicaZone, 1, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type call struct{ host, op string }
			var mu sync.Mutex
			counts := make(map[call]int)
			cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, r *http.Request, op string) bool {
				switch op {
				case "rotate", "encrypt", "decrypt", "re-encrypt", "schedule-deletion":
					if strings.Contains(r.URL.Path, "/"+testkms.KeyID+"/") {
						t.Error("rotation fixture operation reached the configured key")
					}
				}
				mu.Lock()
				defer mu.Unlock()
				counts[call{r.Host, op}]++
				return false
			})
			t.Setenv(upstream.EnvExoscaleKmsKeyId, cfg.KeyID)
			origin, replica := routedRotationClients(t, cfg, endpoint)
			t.Run("rotation", liveRotationProbe(t.Context(), cfg, nil, tc.zone, endpoint, origin, replica).Run)
			u, err := url.Parse(endpoint)
			if err != nil {
				t.Fatal("parse loopback endpoint")
			}
			originHost, replicaHost := "api-"+testkms.Zone+".exoscale.com", "api-"+testkms.ReplicaZone+".exoscale.com"
			mu.Lock()
			defer mu.Unlock()
			for _, want := range []struct {
				at call
				n  int
			}{
				{call{originHost, "rotate"}, tc.originRotates},
				{call{replicaHost, "rotate"}, tc.replicaRotates},
				{call{replicaHost, "schedule-deletion"}, tc.replicaSchedules},
				{call{originHost, "schedule-deletion"}, 1},
				{call{u.Host, "encrypt"}, 2},
				{call{u.Host, "decrypt"}, 2},
				{call{u.Host, "rotate"}, 0},
			} {
				if got := counts[want.at]; got != want.n {
					t.Errorf("%s %s calls = %d, want %d", want.at.host, want.at.op, got, want.n)
				}
			}
		})
	}
}

// routedRotationClients returns raw probe clients for the origin and replica
// zone hostnames. Every connection dials the loopback fake, never the network.
func routedRotationClients(t *testing.T, cfg kmsapi.Config, endpoint string) (conformance.Client, conformance.Client) {
	t.Helper()
	u, err := url.Parse(endpoint)
	cert, readErr := os.ReadFile(cfg.CAFile)
	roots := x509.NewCertPool()
	if err != nil || readErr != nil || !roots.AppendCertsFromPEM(cert) {
		t.Fatal("load loopback KMS endpoint and certificate")
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, u.Host)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	origin := conformance.Client{HTTP: client, Endpoint: "https://api-" + testkms.Zone + ".exoscale.com/v2",
		APIKey: cfg.APIKey, Secret: cfg.APISecret}
	replica := origin
	replica.Endpoint = "https://api-" + testkms.ReplicaZone + ".exoscale.com/v2"
	return origin, replica
}

// TestPluginSealLengthsRejectShortWrap requires the live seal length check to
// reject a valid blob whose wrapped key is one byte shorter than measured, the
// length of the unexplained 222-byte sample of v0.1.0.
func TestPluginSealLengthsRejectShortWrap(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_SEAL_SHORT_CHILD"
	if os.Getenv(child) == "1" {
		cfg, endpoint := testkms.StartWithOverheadSkew(t, -1)
		setFakeEndpointEnv(t, cfg)
		remote := pluginClient(t, "TestServer")
		if err := configureRemote(t.Context(), remote, cfg.KeyID, endpoint); err != nil {
			t.Fatal("configure the test plugin")
		}
		liveDecrypt(t, t.Context(), remote, liveWire(t, t.Context(), remote))
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestPluginSealLengthsRejectShortWrap$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("live plugin blob or wrapped key length differs from the measurement")) {
		t.Fatal("live seal length check accepted a 222-byte wrapped key")
	}
}
