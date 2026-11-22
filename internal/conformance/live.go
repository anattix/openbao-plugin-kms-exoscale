// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

// LiveConfig requires opt-in and resolves credentials without logging their values.
func LiveConfig(t *testing.T) kmsapi.Config {
	t.Helper()
	if os.Getenv("EXOSCALEKMS_LIVE") != "1" {
		t.Skip("set EXOSCALEKMS_LIVE=1 to contact Exoscale")
	}
	settings := map[string]string{"encryption_context": ""}
	if zone := os.Getenv("EXOSCALE_ZONE"); zone == "" {
		settings["zone"] = os.Getenv("EXOSCALEKMS_ZONE")
	}
	cfg, err := kmsapi.Resolve(t.Context(), settings, "", false)
	if err != nil {
		t.Fatal("live probes require a zone, a key UUID and readable credentials")
	}
	if cfg.APIKey == "" || cfg.APISecret == "" {
		t.Fatal("live probe credentials are missing")
	}
	return cfg
}

// LiveClient limits probes to the documented HTTPS zone endpoint with system trust.
func LiveClient(t *testing.T, cfg kmsapi.Config) Client {
	t.Helper()
	if !kmsapi.ValidZone(cfg.Zone) {
		t.Fatal("invalid live probe zone")
	}
	transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	return Client{
		Endpoint: "https://api-" + cfg.Zone + ".exoscale.com/v2",
		APIKey:   cfg.APIKey, Secret: cfg.APISecret,
		Unanswered: TrackUnanswered(t),
		HTTP: &http.Client{
			Transport: transport, Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}
