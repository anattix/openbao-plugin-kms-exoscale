// SPDX-License-Identifier: MPL-2.0

package kmsapi_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

// TestProxyEnvironment gives each case a fresh process because net/http reads
// and caches the proxy environment on its first call.
func TestProxyEnvironment(t *testing.T) {
	for _, name := range []string{
		"connect", "no_proxy", "no_proxy_upper", "direct", "untrusted", "wrong_hostname",
		"connection_refused", "connect_refused", "authenticate", "attempt_deadline", "caller_deadline",
		"https_proxy_h2", "https_proxy_bypass", "https_proxy_untrusted", "https_proxy_origin_untrusted",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProxyEnvironmentChild$")
			cmd.Env = append(os.Environ(), "KMS_TEST_PROXY_CASE="+name)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("proxy case failed: %v\n%s", err, output)
			}
		})
	}
}

// TestProxyEnvironmentChild is the subprocess entry point for TestProxyEnvironment.
func TestProxyEnvironmentChild(t *testing.T) {
	name := os.Getenv("KMS_TEST_PROXY_CASE")
	if name == "" {
		t.Skip("proxy subprocess only")
	}
	for _, variable := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(variable, "")
	}
	var calls, direct, proxied atomic.Int32
	cfg, endpoint := testkms.StartEndpoint(t, func(http.ResponseWriter, *http.Request, string) bool {
		calls.Add(1)
		return false
	})
	origin, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("invalid fake endpoint")
	}
	if name == "wrong_hostname" {
		cfg.Zone = "xx-tst-1"
	}
	authority := "api-" + cfg.Zone + ".exoscale.com:443"

	if strings.HasPrefix(name, "https_proxy_") {
		checkHTTPSProxy(t, name, cfg, origin.Host, authority, &calls, &direct, &proxied)
		return
	}
	if isProxyRoutingCase(name) {
		checkProxyRouting(t, name, cfg, origin.Host, authority, &calls, &direct, &proxied)
		return
	}
	checkProxyFailure(t, name, cfg, origin.Host, authority, &calls, &direct, &proxied)
}

func isProxyRoutingCase(name string) bool {
	switch name {
	case "connect", "no_proxy", "no_proxy_upper", "direct", "untrusted", "wrong_hostname":
		return true
	default:
		return false
	}
}

func checkProxyRouting(t *testing.T, name string, cfg kmsapi.Config, addr, authority string, calls, direct, proxied *atomic.Int32) {
	t.Helper()
	proxy, tunnels := testkms.StartConnectProxy(t, authority, addr)
	switch name {
	case "connect", "untrusted", "wrong_hostname":
		t.Setenv("HTTPS_PROXY", proxy)
	case "no_proxy":
		t.Setenv("https_proxy", proxy)
		t.Setenv("no_proxy", "api-"+testkms.ReplicaZone+".exoscale.com")
	case "no_proxy_upper":
		t.Setenv("HTTPS_PROXY", proxy)
		t.Setenv("NO_PROXY", "api-"+testkms.ReplicaZone+".exoscale.com")
	}
	instrumentProxyDial(&cfg, addr, strings.TrimPrefix(proxy, "http://"), direct, proxied)
	if name == "untrusted" {
		cfg.CAFile = ""
	}
	rejected := name == "untrusted" || name == "wrong_hostname"
	if rejected {
		assertProxyError(t, cfg, t.Context(), "tls verification failed", "")
	} else {
		roundTripThroughClient(t, cfg, true)
	}
	if name == "direct" {
		assertProxyCounts(t, calls, direct, proxied, 2, 1, 0)
		return
	}
	if rejected {
		assertProxyCounts(t, calls, direct, proxied, 0, 0, 1)
	} else {
		assertProxyCounts(t, calls, direct, proxied, 2, 0, 1)
	}
	select {
	case obs := <-tunnels:
		if !obs.ConnectOnly || !obs.TLS {
			t.Fatal("proxy did not observe a header-only CONNECT followed by TLS")
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not observe a tunnel")
	}
	if name == "no_proxy" || name == "no_proxy_upper" {
		cfg.Zone = testkms.ReplicaZone
		roundTripThroughClient(t, cfg, true)
		assertProxyCounts(t, calls, direct, proxied, 4, 1, 1)
	}
}

func roundTripThroughClient(t *testing.T, cfg kmsapi.Config, wantHTTP2 bool) {
	t.Helper()
	client, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal("cannot construct KMS client")
	}
	plain := []byte("tunnel-fixture")
	sealed, err := client.Encrypt(t.Context(), cfg.KeyID, plain)
	if err != nil {
		t.Fatalf("fake encrypt failed: %v", err)
	}
	cleartext, err := client.Decrypt(t.Context(), cfg.KeyID, sealed)
	if err != nil || string(cleartext) != string(plain) {
		t.Fatal("fake decrypt did not recover the fixture")
	}
	if kmsapi.AttemptsHTTP2(client) != wantHTTP2 {
		t.Fatal("unexpected HTTP/2 offer for the selected route")
	}
}

func instrumentProxyDial(cfg *kmsapi.Config, directAddr, proxyAddr string, direct, proxied *atomic.Int32) {
	cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == proxyAddr {
			proxied.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		direct.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, directAddr)
	}
}

func assertProxyCounts(t *testing.T, calls, direct, dialProxy *atomic.Int32, wantCalls, wantDirect, wantProxy int32) {
	t.Helper()
	if a, b, c := calls.Load(), direct.Load(), dialProxy.Load(); a != wantCalls || b != wantDirect || c != wantProxy {
		t.Fatalf("fake calls, direct dials, proxy dials = %d, %d, %d; want %d, %d, %d", a, b, c, wantCalls, wantDirect, wantProxy)
	}
}

func checkProxyFailure(t *testing.T, name string, cfg kmsapi.Config, addr, authority string, calls, direct, proxied *atomic.Int32) {
	t.Helper()
	const userMarker = "synthetic-user-marker"
	const passMarker = "synthetic-pass-marker"
	ctx := t.Context()
	want, attempts := "transport failed", int32(2)
	var connects atomic.Int32
	proxyAddr := failureProxy(t, name, authority, userMarker+" "+passMarker, &connects)
	wantConnects := attempts
	bound := 2 * time.Second
	switch name {
	case "connection_refused":
		want, wantConnects = "connection refused", 0
	case "authenticate":
		attempts, wantConnects = 1, 1
	case "attempt_deadline":
		cfg.Timeout = 150 * time.Millisecond
		want = "attempt timeout: context deadline exceeded"
	case "caller_deadline":
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		want, attempts, wantConnects = "context deadline exceeded", 1, 1
	}
	proxy := url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword(userMarker, passMarker)}
	t.Setenv("HTTPS_PROXY", proxy.String())
	instrumentProxyDial(&cfg, addr, proxyAddr, direct, proxied)

	start := time.Now()
	assertProxyError(t, cfg, ctx, want, userMarker+" "+passMarker)
	if elapsed := time.Since(start); elapsed > bound {
		t.Fatalf("proxy failure escaped the call bound: %s", elapsed)
	}
	assertProxyCounts(t, calls, direct, proxied, 0, 0, attempts)
	if connects.Load() != wantConnects {
		t.Fatalf("proxy CONNECT count = %d; want %d", connects.Load(), wantConnects)
	}
}

func failureProxy(t *testing.T, name, authority, reason string, connects *atomic.Int32) string {
	t.Helper()
	if name == "connection_refused" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("cannot reserve a closed proxy port")
		}
		addr := listener.Addr().String()
		if listener.Close() != nil {
			t.Fatal("cannot close the proxy port")
		}
		return addr
	}
	stop := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != authority {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		connects.Add(1)
		if name == "attempt_deadline" || name == "caller_deadline" {
			select {
			case <-r.Context().Done():
			case <-stop:
			}
			return
		}
		conn, wire, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close() // This fixture owns its hijacked connection.
		status := http.StatusServiceUnavailable
		if name == "authenticate" {
			status = http.StatusProxyAuthRequired
		}
		if _, err := fmt.Fprintf(wire, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, reason); err == nil {
			_ = wire.Flush() // The test detects any failure to deliver the response.
		}
	}))
	t.Cleanup(proxy.Close)
	t.Cleanup(func() { close(stop) })
	return strings.TrimPrefix(proxy.URL, "http://")
}

func assertProxyError(t *testing.T, cfg kmsapi.Config, ctx context.Context, want, privateMarkers string) {
	t.Helper()
	client, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal("cannot construct KMS client")
	}
	sealed, err := client.Encrypt(ctx, cfg.KeyID, []byte("tunnel-fixture"))
	if err == nil || len(sealed) != 0 {
		t.Fatal("proxy failure did not fail closed")
	}
	for _, marker := range strings.Fields(privateMarkers) {
		if strings.Contains(err.Error(), marker) {
			t.Fatal("proxy URL user information reached the diagnostic")
		}
	}
	if err.Error() != "Exoscale KMS encrypt: "+want {
		t.Fatal("proxy failure did not return the fixed diagnostic")
	}
}

// checkHTTPSProxy relays through an https:// proxy whose TLS listener offers
// HTTP/2 as well as HTTP/1.1, as many TLS-terminating proxies do. The client
// must reach it with HTTP/1.1 so that its CONNECT can be parsed.
func checkHTTPSProxy(t *testing.T, name string, cfg kmsapi.Config, addr, authority string, calls, direct, proxied *atomic.Int32) {
	t.Helper()
	var connects atomic.Int32
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.RequestURI != authority || r.Host != authority ||
			r.ProtoMajor != 1 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
			r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "" {
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
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	t.Cleanup(proxy.Close)

	proxyAddr := proxy.Listener.Addr().String()
	t.Setenv("HTTPS_PROXY", "https://"+proxyAddr)
	instrumentProxyDial(&cfg, addr, proxyAddr, direct, proxied)

	var wantConnects int32
	switch name {
	case "https_proxy_bypass":
		t.Setenv("NO_PROXY", "api-"+cfg.Zone+".exoscale.com")
		roundTripThroughClient(t, cfg, true)
		assertProxyCounts(t, calls, direct, proxied, 2, 1, 0)
	case "https_proxy_untrusted":
		assertProxyError(t, cfg, t.Context(), "tls verification failed", "")
		assertProxyCounts(t, calls, direct, proxied, 0, 0, 1)
	case "https_proxy_origin_untrusted":
		cfg.CAFile = trustProxy(t, proxy, "")
		assertProxyError(t, cfg, t.Context(), "tls verification failed", "")
		assertProxyCounts(t, calls, direct, proxied, 0, 0, 1)
		wantConnects = 1
	case "https_proxy_h2":
		cfg.CAFile = trustProxy(t, proxy, cfg.CAFile)
		roundTripThroughClient(t, cfg, false)
		assertProxyCounts(t, calls, direct, proxied, 2, 0, 1)
		wantConnects = 1
	default:
		t.Fatal("unknown HTTPS proxy case")
	}
	if got := connects.Load(); got != wantConnects {
		t.Fatalf("HTTPS proxy CONNECT count = %d; want %d", got, wantConnects)
	}
}

func trustProxy(t *testing.T, proxy *httptest.Server, originCA string) string {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})
	if originCA != "" {
		ca, err := os.ReadFile(originCA)
		if err != nil {
			t.Fatal("cannot read the fake KMS CA")
		}
		pemBytes = append(pemBytes, ca...)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal("cannot write the fake CA file")
	}
	return path
}
