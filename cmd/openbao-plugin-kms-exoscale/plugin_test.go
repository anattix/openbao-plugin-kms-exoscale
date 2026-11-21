// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/plugin/v2/plugintest"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	upstream "github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

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
	t.Setenv("SSL_CERT_FILE", cfg.CAFile)
	t.Setenv("EXOSCALE_API_KEY", cfg.APIKey)
	t.Setenv("EXOSCALE_API_SECRET", cfg.APISecret)
	t.Setenv("EXOSCALEKMS_ENDPOINT", "")
	t.Setenv("EXOSCALEKMS_KEY_ID", "")
	t.Setenv("EXOSCALEKMS_ZONE", "")
	return cfg, endpoint
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
	// The fake emits 4 version bytes, 12 nonce bytes, a 32-byte DEK and a
	// 16-byte tag. The check catches an extra zone prefix or mechanism field.
	if string(key[3]) != keyID || len(key[5]) != 64 {
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
		{"unknown key", "44444444-4444-4444-8444-444444444444", "get", "HTTP 400 (key not found)", nil},
		{"disabled key", testkms.DisabledID, "encrypt", "HTTP 400 (key disabled)", nil},
		{"refused credential", testkms.KeyID, "get", "HTTP 401", nil},
		{"remote error redaction", testkms.KeyID, "encrypt", "HTTP 400", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"message":"`+marker+`","title":"`+marker+`"}`)
		}},
		{"truncated answer", testkms.KeyID, "encrypt", "request failed or invalid response", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, `{"ciphertext":"`)
		}},
		{"malformed answer", testkms.KeyID, "encrypt", "request failed or invalid response", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"ciphertext":"not base64"}`)
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
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), marker) {
				t.Fatal("expected sanitized failure class:", tc.want)
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
