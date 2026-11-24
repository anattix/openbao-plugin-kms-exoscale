// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

// TestPluginHTTPSProxy pins what the README states for the seal behind an
// https:// proxy. The upstream SDK offers HTTP/2 to the proxy and then writes
// an HTTP/1.1 CONNECT, so a proxy that selects HTTP/2 makes the call fail
// closed. A proxy limited to HTTP/1.1 works, and so does an HTTP/2-capable
// proxy when GODEBUG=http2client=0 is in the plugin environment.
func TestPluginHTTPSProxy(t *testing.T) {
	for _, name := range []string{"http1_proxy", "http2_proxy", "http2_proxy_godebug"} {
		t.Run(name, func(t *testing.T) {
			var calls, connects atomic.Int32
			cfg, endpoint := fakeEndpoint(t, func(http.ResponseWriter, *http.Request, string) bool {
				calls.Add(1)
				return false
			})
			origin, err := url.Parse(endpoint)
			if err != nil {
				t.Fatal("invalid fake endpoint")
			}
			authority := testkms.ProxyHost + ":443"
			proxy := startTLSConnectProxy(t, authority, origin.Host, name != "http1_proxy", &connects)
			t.Setenv("SSL_CERT_FILE", proxyTrustBundle(t, proxy, cfg.CAFile))
			t.Setenv("HTTPS_PROXY", "https://"+proxy.Listener.Addr().String())
			t.Setenv("https_proxy", "")
			t.Setenv("NO_PROXY", "")
			t.Setenv("no_proxy", "")
			godebug := ""
			if name == "http2_proxy_godebug" {
				godebug = "http2client=0"
			}
			t.Setenv("GODEBUG", godebug)

			if name == "http2_proxy" {
				remote := pluginClient(t, "TestFastServer")
				start := time.Now()
				err := configureRemote(t.Context(), remote, cfg.KeyID, "https://"+authority+"/v2")
				if err == nil || time.Since(start) > 3*time.Second || calls.Load() != 0 || connects.Load() != 0 {
					t.Fatal("seal did not fail closed through an HTTP/2 proxy")
				}
				if !strings.Contains(err.Error(), "Exoscale KMS configure: ") {
					t.Fatal("seal configuration did not return the fixed diagnostic")
				}
				return
			}
			remote := pluginClient(t, "TestServer")
			ctx := t.Context()
			if err := configureRemote(ctx, remote, cfg.KeyID, "https://"+authority+"/v2"); err != nil {
				t.Fatal("plugin did not configure through the https:// proxy")
			}
			payload := []byte("synthetic seal fixture")
			blob, err := remote.Encrypt(ctx, payload)
			if err != nil {
				t.Fatal("plugin did not encrypt through the https:// proxy")
			}
			got, err := remote.Decrypt(ctx, blob)
			defer clear(got)
			if err != nil || !bytes.Equal(got, payload) || calls.Load() != 3 || connects.Load() == 0 {
				t.Fatal("https:// proxy round trip did not tunnel all three calls")
			}
		})
	}
}

// startTLSConnectProxy relays one header-only HTTP/1.1 CONNECT for authority
// to addr. With http2 set, its TLS listener also offers HTTP/2.
func startTLSConnectProxy(t *testing.T, authority, addr string, http2 bool, connects *atomic.Int32) *httptest.Server {
	t.Helper()
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.ProtoMajor != 1 || r.RequestURI != authority ||
			r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		connects.Add(1)
		upstream, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close() // This fixture owns its relay connections.
		downstream, wire, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer downstream.Close() // This fixture owns its hijacked connection.
		deadline := time.Now().Add(5 * time.Second)
		if downstream.SetDeadline(deadline) != nil || upstream.SetDeadline(deadline) != nil {
			return
		}
		if _, err := wire.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || wire.Flush() != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(upstream, wire) // A closed peer is expected at teardown.
			_ = upstream.Close()           // Unblock the copy below.
		}()
		_, _ = io.Copy(downstream, upstream) // A closed peer is expected at teardown.
		_ = downstream.Close()               // Unblock the copy above.
		<-done
	}))
	proxy.EnableHTTP2 = http2
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	return proxy
}

// proxyTrustBundle writes the proxy certificate and the fake KMS CA to one
// file for SSL_CERT_FILE, so the seal verifies both TLS legs.
func proxyTrustBundle(t *testing.T, proxy *httptest.Server, kmsCA string) string {
	t.Helper()
	ca, err := os.ReadFile(kmsCA)
	if err != nil {
		t.Fatal("cannot read the fake KMS CA")
	}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), ca...)
	path := filepath.Join(t.TempDir(), "trust.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal("cannot write the trust bundle")
	}
	return path
}
