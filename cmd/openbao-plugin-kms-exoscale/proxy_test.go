// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

// TestPluginProxy verifies that the plugin process's SDK uses verified TLS
// through an HTTP CONNECT tunnel.
func TestPluginProxy(t *testing.T) {
	var calls atomic.Int32
	cfg, endpoint := fakeEndpoint(t, func(http.ResponseWriter, *http.Request, string) bool {
		calls.Add(1)
		return false
	})
	origin, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("invalid fake endpoint")
	}
	// Use a non-loopback hostname from the certificate. Go exempts loopback
	// destinations from proxy selection.
	authority := testkms.ProxyHost + ":443"
	proxy, tunnels := testkms.StartConnectProxy(t, authority, origin.Host)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", proxy)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	remote := pluginClient(t, "TestServer")
	ctx := t.Context()
	if err := configureRemote(ctx, remote, cfg.KeyID, "https://"+authority+"/v2"); err != nil {
		t.Fatal("plugin did not configure through the proxy")
	}
	payload := []byte("synthetic seal fixture")
	blob, err := remote.Encrypt(ctx, payload)
	if err != nil {
		t.Fatal("plugin did not encrypt through the proxy")
	}
	got, err := remote.Decrypt(ctx, blob)
	defer clear(got)
	if err != nil || !bytes.Equal(got, payload) || calls.Load() != 3 {
		t.Fatal("proxy round trip did not use the fake KMS for all three calls")
	}
	select {
	case obs := <-tunnels:
		if !obs.ConnectOnly || !obs.TLS {
			t.Fatal("proxy did not observe a header-only CONNECT followed by TLS")
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not observe a tunnel")
	}
}

// TestPluginProxyBypassAndFailure checks NO_PROXY and failing proxies for the
// seal process. The fast server's 500 ms call budget bounds each failure.
func TestPluginProxyBypassAndFailure(t *testing.T) {
	const userMarker, passMarker = "synthetic-user-marker", "synthetic-pass-marker"
	for _, name := range []string{"no_proxy", "refusing", "unreachable"} {
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
			authority := net.JoinHostPort(testkms.ProxyHost, origin.Port())
			t.Setenv("KMS_TEST_PROXY_DNS", startProxyTestDNS(t))
			proxy := url.URL{Scheme: "http", User: url.UserPassword(userMarker, passMarker)}
			noProxy := ""
			switch name {
			case "no_proxy":
				// A proxy that could relay successfully would mask a missed bypass.
				// Count every CONNECT independently of whether TLS starts.
				proxy.Host = refusingPluginProxy(t, "unexpected CONNECT", &connects)
				noProxy = testkms.ProxyHost
			case "refusing":
				proxy.Host = refusingPluginProxy(t, userMarker+" "+passMarker, &connects)
			case "unreachable":
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal("cannot reserve a closed proxy port")
				}
				proxy.Host = listener.Addr().String()
				if listener.Close() != nil {
					t.Fatal("cannot close the proxy port")
				}
			}
			t.Setenv("HTTPS_PROXY", proxy.String())
			t.Setenv("https_proxy", "")
			t.Setenv("NO_PROXY", noProxy)
			t.Setenv("no_proxy", "")

			remote := pluginClient(t, "TestProxyTestServer")
			start := time.Now()
			err = configureRemote(t.Context(), remote, cfg.KeyID, "https://"+authority+"/v2")
			if name == "no_proxy" {
				if connects.Load() != 0 || calls.Load() != 1 || err != nil {
					t.Fatal("NO_PROXY did not reach the fake directly without CONNECT")
				}
				return
			}
			if err == nil || time.Since(start) > 3*time.Second || calls.Load() != 0 {
				t.Fatal("seal configuration did not fail closed within the call budget")
			}
			if strings.Contains(err.Error(), userMarker) || strings.Contains(err.Error(), passMarker) {
				t.Fatal("proxy URL user information reached the diagnostic")
			}
			if !strings.Contains(err.Error(), "Exoscale KMS configure: ") {
				t.Fatal("seal configuration did not return the fixed diagnostic")
			}
			if name == "refusing" && connects.Load() == 0 {
				t.Fatal("the seal did not send CONNECT to the configured proxy")
			}
		})
	}
}

func refusingPluginProxy(t *testing.T, reason string, connects *atomic.Int32) string {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, wire, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close() // This fixture owns its hijacked connection.
		if _, err := fmt.Fprintf(wire, "HTTP/1.1 407 %s\r\nContent-Length: 0\r\n\r\n", reason); err != nil {
			return
		}
		connects.Add(1)
		_ = wire.Flush() // The CONNECT client may have closed the connection.
	}))
	t.Cleanup(proxy.Close)
	return strings.TrimPrefix(proxy.URL, "http://")
}

// TestProxyTestServer runs the fast seal with DNS restricted to the loopback
// fixture. The fake name is neither a Go proxy exemption nor publicly resolved.
func TestProxyTestServer(t *testing.T) {
	addr := os.Getenv("KMS_TEST_PROXY_DNS")
	if addr == "" {
		t.Skip("requires a loopback DNS fixture")
	}
	resolver := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = resolver })
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", addr)
		},
	}
	TestFastServer(t)
}

func startProxyTestDNS(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen on loopback for fake DNS")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var packet [512]byte
		for {
			n, from, err := conn.ReadFrom(packet[:])
			if err != nil {
				return // Cleanup closes the socket.
			}
			if reply := proxyTestDNSReply(packet[:n]); reply != nil {
				_, _ = conn.WriteTo(reply, from) // Client cancellation can close the peer.
			}
		}
	}()
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error("close fake DNS socket")
		}
		<-done
	})
	return conn.LocalAddr().String()
}

// proxyTestDNSReply answers one standard query with the loopback address for
// the fixture name, an empty answer for its other types and NXDOMAIN for any
// other name. It uses only the standard library so that the module keeps its
// direct requirements.
func proxyTestDNSReply(packet []byte) []byte {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return nil
	}
	end := 12
	var labels []string
	for {
		if end >= len(packet) {
			return nil
		}
		size := int(packet[end])
		end++
		if size == 0 {
			break
		}
		if size > 63 || end+size > len(packet) {
			return nil
		}
		labels = append(labels, string(packet[end:end+size]))
		end += size
	}
	if end+4 > len(packet) {
		return nil
	}
	queryType := binary.BigEndian.Uint16(packet[end : end+2])
	end += 4
	// Copy the header and the question only; drop any EDNS record.
	reply := append([]byte(nil), packet[:end]...)
	// Keep the opcode and RD bit, set QR and RA.
	flags := binary.BigEndian.Uint16(packet[2:4])&0x7900 | 0x8080
	var answers uint16
	switch {
	case !strings.EqualFold(strings.Join(labels, "."), testkms.ProxyHost):
		flags |= 3 // NXDOMAIN
	case queryType == 1: // A
		answers = 1
		// Name pointer to the question, type A, class IN, TTL 0, 127.0.0.1.
		reply = append(reply, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
	}
	binary.BigEndian.PutUint16(reply[2:4], flags)
	binary.BigEndian.PutUint16(reply[6:8], answers)
	binary.BigEndian.PutUint16(reply[8:10], 0)
	binary.BigEndian.PutUint16(reply[10:12], 0)
	return reply
}

// TestPluginProxyDiagnosticRedaction exercises the guard even if SDK retries
// convert a proxy-controlled error into a context deadline before it arrives.
func TestPluginProxyDiagnosticRedaction(t *testing.T) {
	const marker = "synthetic diagnostic marker"
	transportErr := &url.Error{Op: http.MethodConnect, URL: "https://" + testkms.ProxyHost, Err: errors.New(marker)}
	got := publicError(t.Context(), "configure", transportErr)
	if got == nil || strings.Contains(got.Error(), marker) {
		t.Fatal("raw proxy transport text reached the public diagnostic")
	}
}
