// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TunnelObservation describes the cleartext CONNECT and the first TLS record.
type TunnelObservation struct {
	ConnectOnly bool
	TLS         bool
}

// StartConnectProxy relays a CONNECT for authority to a loopback fake address.
func StartConnectProxy(t *testing.T, authority, addr string) (string, <-chan TunnelObservation) {
	t.Helper()
	observed := make(chan TunnelObservation, 1)
	observe := func(observation TunnelObservation) {
		select {
		case observed <- observation:
		default:
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := r.Method == http.MethodConnect && r.RequestURI == authority &&
			r.Host == authority && r.ContentLength == 0 && len(r.TransferEncoding) == 0 &&
			r.Header.Get("Authorization") == "" && r.Header.Get("Content-Type") == ""
		if !clean {
			observe(TunnelObservation{})
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		relayTunnel(w, addr, observe)
	}))
	t.Cleanup(server.Close)
	return server.URL, observed
}

func relayTunnel(w http.ResponseWriter, addr string, observe func(TunnelObservation)) {
	upstream, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer upstream.Close() // Closing releases the relay even if the peer disconnects.
	downstream, wire, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer downstream.Close() // Hijacked connections are owned by this relay.
	deadline := time.Now().Add(5 * time.Second)
	if downstream.SetDeadline(deadline) != nil || upstream.SetDeadline(deadline) != nil {
		return
	}
	if _, err := wire.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || wire.Flush() != nil {
		return
	}
	var header [3]byte
	if _, err := io.ReadFull(wire, header[:]); err != nil {
		return
	}
	observe(TunnelObservation{ConnectOnly: true, TLS: header[0] == 0x16 && header[1] == 0x03})
	if _, err := upstream.Write(header[:]); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer downstream.Close()             // Unblock the peer copy when the upstream side closes.
		_, _ = io.Copy(downstream, upstream) // A closed peer is expected at tunnel teardown.
	}()
	_, _ = io.Copy(upstream, wire) // A closed peer is expected at tunnel teardown.
	_ = upstream.Close()           // Unblock the peer copy before waiting for it.
	<-done
}

// ClearProxyEnvironment removes an inherited proxy from an offline test
// process. net/http reads the proxy variables once per process, and the fake
// routes every dial to loopback, so an ambient HTTPS_PROXY would send the
// fake a CONNECT instead of a KMS request. Live runs keep the environment.
func ClearProxyEnvironment() {
	if os.Getenv("EXOSCALEKMS_LIVE") == "1" {
		return
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		_ = os.Unsetenv(name) // Unsetenv fails only for invalid names.
	}
}
