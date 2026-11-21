// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	egoscale "github.com/exoscale/egoscale/v3"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func TestProblemDetails(t *testing.T) {
	for _, tc := range []struct{ name, id, title string }{
		{"unknown", "44444444-4444-4444-8444-444444444444", "Key Not Found"},
		{"disabled", DisabledID, "Key is Disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, srv := start(t, nil)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v2/kms-key/"+tc.id+"/rotate", nil)
			if err != nil || egoscale.SignHTTPRequest(req, fixtureKey, fixtureSecret, time.Now().Add(time.Minute)) != nil {
				t.Fatal("prepare signed fixture request")
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal("send fixture request")
			}
			defer resp.Body.Close() // Decoded below.
			var problem struct {
				Type   string `json:"type"`
				Title  string `json:"title"`
				Status int    `json:"status"`
			}
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Content-Type") != "application/problem+json" ||
				json.NewDecoder(resp.Body).Decode(&problem) != nil || problem.Type != "about:blank" ||
				problem.Title != tc.title || problem.Status != resp.StatusCode {
				t.Fatal("expected HTTP 400 with the documented KMS problem type")
			}
		})
	}
}

func TestRotationAdvancesFakeKeyVersion(t *testing.T) {
	cfg, rotate := StartWithRotation(t)
	client, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	old, err := client.Encrypt(t.Context(), cfg.KeyID, make([]byte, kmsapi.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	rotate()
	fresh, err := client.Encrypt(t.Context(), cfg.KeyID, make([]byte, kmsapi.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if len(old) <= 4 || len(fresh) <= 4 || old[3] != 0 || fresh[3] != 1 {
		t.Fatal("rotation did not change the fake ciphertext version")
	}
}
