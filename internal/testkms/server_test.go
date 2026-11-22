// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func TestMeasuredWireContract(t *testing.T) {
	cfg, srv := start(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
		id, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v2/kms-key/"), "/")
		if id == KeyID {
			switch op {
			case "rotate", "disable", "enable", "schedule-deletion", "cancel-deletion", "replicate":
				t.Errorf("configured key received %s", op)
				http.Error(w, "", http.StatusBadRequest)
				return true
			}
		}
		return false
	})
	origin, replica := routedProbeClients(t, cfg, srv)
	conformance.Data(t, origin, KeyID)
	t.Run("paced_requests", func(t *testing.T) { conformance.Rate(t, origin, KeyID) })
	t.Run("replica", func(t *testing.T) { conformance.Replica(t, origin, replica, KeyID) })
	t.Run("rotation", func(t *testing.T) {
		(conformance.RotationProbe{Origin: origin, Replica: replica, ConfiguredKey: KeyID, ReplicaZone: ReplicaZone}).Run(t)
	})
	t.Run("disposable", func(t *testing.T) { conformance.Disposable(t, origin, KeyID, ReplicaZone) })
	t.Run("configured_key_still_enabled", func(t *testing.T) {
		api, err := kmsapi.New(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.Encrypt(t.Context(), KeyID, make([]byte, 32)); err != nil {
			t.Fatal("disposable probe touched the configured key")
		}
	})
}

// Route both logical zone hostnames to the same in-process fake.
func routedProbeClients(t *testing.T, cfg kmsapi.Config, srv *httptest.Server) (conformance.Client, conformance.Client) {
	t.Helper()
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{
		Transport:     transport,
		Timeout:       cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	origin := conformance.Client{HTTP: client, Endpoint: "https://api-" + Zone + ".exoscale.com/v2", APIKey: cfg.APIKey, Secret: cfg.APISecret}
	replica := origin
	replica.Endpoint = "https://api-" + ReplicaZone + ".exoscale.com/v2"
	return origin, replica
}

// TestPayloadBoundRejectsPresentContentType verifies that the measured
// refusal assertion runs on the complete HTTP response, including its headers.
func TestPayloadBoundRejectsPresentContentType(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_PAYLOAD_BOUND_CHILD"
	if os.Getenv(child) == "1" {
		const maxMeasuredRefused = 786432
		bodyBytes := int64(base64.StdEncoding.EncodedLen(maxMeasuredRefused) + len(`{"plaintext":""}`))
		cfg, srv := start(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
			if op != "encrypt" || r.ContentLength != bodyBytes {
				return false
			}
			w.Header().Set("Content-Type", "")
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("server error")); err != nil {
				t.Error("write fake payload refusal")
			}
			return true
		})
		conformance.Data(t, testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), KeyID)
		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestPayloadBoundRejectsPresentContentType$/^payload_bound$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(out, []byte("payload refusal differs from measured HTTP 500 without Content-Type")) {
		t.Fatal("payload-bound probe did not reject a present Content-Type header")
	}
}

// TestMeasuredUnknownCredentialRequest checks the fixture independently of
// the fake's response, which is the same for either unknown key format.
func TestMeasuredUnknownCredentialRequest(t *testing.T) {
	var unknownAPIKeyRequests atomic.Int32
	keyFormat := regexp.MustCompile(`^EXO[0-9a-f]{24}$`)
	cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v2/kms-key/"+KeyID {
			_, params, _ := strings.Cut(r.Header.Get("Authorization"), " credential=")
			key, _, _ := strings.Cut(params, ",")
			if key != fixtureKey {
				unknownAPIKeyRequests.Add(1)
				if !keyFormat.MatchString(key) {
					t.Error("unknown API key does not have the measured EXO format")
				}
				if !validSignature(r, nil, key, fixtureSecret+"-conformance-invalid") {
					t.Error("unknown API key probe was not signed with the wrong secret")
				}
			}
		}
		next.ServeHTTP(w, r)
	})
	conformance.Data(t, testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), KeyID)
	if unknownAPIKeyRequests.Load() != 1 {
		t.Error("expected exactly one unknown API key metadata request")
	}
}

// The child is expected to fail. Its parent checks that cleanup ran and
// confirmed pending deletion after that failure.
func TestDisposableCleanupAfterFailure(t *testing.T) {
	if os.Getenv("EXOSCALEKMS_TEST_CLEANUP_CHILD") == "1" {
		var enabled atomic.Bool
		cfg, srv := start(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
			if op == "enable" {
				enabled.Store(true)
			}
			if op == "generate-data-key" || (op == "schedule-deletion" && !enabled.Load()) {
				http.Error(w, "", http.StatusInternalServerError)
				return true
			}
			if strings.Contains(r.URL.Path, "/"+KeyID+"/") && op == "schedule-deletion" {
				t.Error("configured key reached cleanup route")
				http.Error(w, "", http.StatusInternalServerError)
				return true
			}
			return false
		})
		c := conformance.Client{HTTP: srv.Client(), Endpoint: srv.URL + "/v2", APIKey: cfg.APIKey, Secret: cfg.APISecret}
		conformance.Disposable(t, c, KeyID, ReplicaZone)
		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestDisposableCleanupAfterFailure$")
	cmd.Env = append(os.Environ(), "EXOSCALEKMS_TEST_CLEANUP_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("expected HTTP 400, got HTTP 500")) ||
		!bytes.Contains(output, []byte("KMS disposable_cleanup status=pending-deletion delay_days=7")) ||
		bytes.Contains(output, []byte("configured key reached cleanup route")) {
		t.Fatal("post-failure cleanup did not schedule only the disposable key")
	}
}

func TestRefusalFixturesHaveOnlyMeasuredFields(t *testing.T) {
	for _, tc := range []struct {
		name, wantType, wantTitle string
		write                     func(http.ResponseWriter)
	}{
		{"both generation selectors", "#/http-problem-types/request-invalid-parameters", "Invalid argument", func(w http.ResponseWriter) {
			count := 16
			generationLength(w, message{KeySpec: "AES-256", BytesCount: &count})
		}},
		{"ciphertext of another key", "", "", func(w http.ResponseWriter) {
			reportCiphertextError(w, errOtherKey)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.write(rec)
			var observed struct {
				Type, Title string
				Status      int
			}
			if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &observed) != nil ||
				observed.Status != rec.Code || observed.Type != tc.wantType || observed.Title != tc.wantTitle {
				t.Fatal("fake response differs from the captured fields")
			}
		})
	}
}

// TestMeasuredLengthsAcrossRotation exercises the live data and rotation probes
// on both sides of the version 9 to 10 boundary.
func TestMeasuredLengthsAcrossRotation(t *testing.T) {
	cfg, srv := start(t, nil)
	origin, replica := routedProbeClients(t, cfg, srv)
	cfg.KeyID = createRotationFixture(t, cfg, srv, true)
	replicateRotationFixture(t, cfg, srv)
	client, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal("configure fake KMS client")
	}
	for range 8 {
		rotateFixtureKey(t, cfg, srv)
	}
	plain := make([]byte, 32)
	old, err := client.Encrypt(t.Context(), cfg.KeyID, plain)
	if err != nil || len(old) != 223 {
		t.Fatal("version 9 must wrap 32 bytes to 223 bytes")
	}
	t.Run("version_9", func(t *testing.T) { conformance.Data(t, origin, cfg.KeyID) })
	rotateFixtureKey(t, cfg, srv)
	t.Run("version_10", func(t *testing.T) {
		fresh, err := client.Encrypt(t.Context(), cfg.KeyID, plain)
		if err != nil || len(fresh) != 224 {
			t.Fatal("version 10 must wrap 32 bytes to 224 bytes")
		}
		got, err := client.Decrypt(t.Context(), cfg.KeyID, old)
		defer clear(got)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("a version 9 ciphertext must remain readable after rotation")
		}
		conformance.Data(t, origin, cfg.KeyID)
		t.Run("replica", func(t *testing.T) {
			conformance.Replica(t, origin, replica, cfg.KeyID)
		})
	})
	rotateFixtureKey(t, cfg, srv)
	t.Run("version_11", func(t *testing.T) { conformance.Data(t, origin, cfg.KeyID) })
}

// TestUnmeasuredFakeVersion checks the fake's ciphertext boundary without
// performing automatic rotations.
func TestUnmeasuredFakeVersion(t *testing.T) {
	for _, tc := range []struct {
		version  uint32
		overhead int
	}{{0, 0}, {1, 191}, {12, 192}, {99, 192}, {100, 0}} {
		wrapped, err := wrap(KeyID, tc.version, 0, make([]byte, 32), nil)
		if tc.overhead == 0 {
			if err == nil || len(wrapped) != 0 {
				t.Errorf("fake emitted a ciphertext for unsupported version %d", tc.version)
			}
			continue
		}
		if err != nil || len(wrapped) != 32+tc.overhead {
			t.Errorf("fake used the wrong overhead for version %d", tc.version)
		}
	}
}

// TestLengthAssertionsRejectSkewedOverhead runs the live probes on a fake whose
// valid ciphertexts are two bytes longer than measured. Each probe that asserts
// a length must fail; a probe whose assertion was dropped would pass.
func TestLengthAssertionsRejectSkewedOverhead(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_SKEW_CHILD"
	if os.Getenv(child) == "1" {
		cfg, srv := startFake(t, nil, nil, 2)
		origin, replica := routedProbeClients(t, cfg, srv)
		conformance.Data(t, origin, KeyID)
		t.Run("replica", func(t *testing.T) { conformance.Replica(t, origin, replica, KeyID) })
		t.Run("rotation", func(t *testing.T) { (conformance.RotationProbe{Origin: origin, ConfiguredKey: KeyID}).Run(t) })
		t.Run("disposable", func(t *testing.T) { conformance.Disposable(t, origin, KeyID, ReplicaZone) })
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestLengthAssertionsRejectSkewedOverhead$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatal("expected the child probes to fail normally")
	}
	const name = "TestLengthAssertionsRejectSkewedOverhead/"
	for _, sub := range []string{
		"generate_data_key/aes_256", "generate_data_key/one_byte", "generate_data_key/64_bytes",
		"generate_data_key/1024_bytes", "ciphertext_shape", "payload_bound", "same_key_reencrypt",
		"replica", "rotation", "disposable/different_key_reencrypt",
	} {
		if !bytes.Contains(out, []byte("--- FAIL: "+name+sub+" (")) {
			t.Errorf("%s accepted a ciphertext two bytes longer than measured", sub)
		}
	}
	for _, sub := range []string{"encryption_context", "disposable/ciphertext_of_another_key"} {
		if !bytes.Contains(out, []byte("--- PASS: "+name+sub+" (")) {
			t.Errorf("%s must not depend on ciphertext length", sub)
		}
	}
	for _, label := range []string{"rotation_old: ", "rotation_fresh: ", "rotation_rewrapped: "} {
		if !bytes.Contains(out, []byte(label+"ciphertext overhead at material version")) {
			t.Errorf("rotation did not report %s", label)
		}
	}
	if bytes.Count(out, []byte("plaintext bytes: got 193, want 191")) != 15 {
		t.Error("an expected raw length diagnostic was absent")
	}
	for _, label := range []string{"origin", "replica"} {
		if !bytes.Contains(out, []byte(label+" ciphertext length is outside the measured sizes")) {
			t.Errorf("%s replica path accepted skewed overhead", label)
		}
	}
	for _, size := range []int{1, 16, 32, 4096, 65536} {
		want := fmt.Sprintf("ciphertext_shape: ciphertext overhead at material version 1 with %d plaintext bytes", size)
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("ciphertext shape stopped checking size %d", size)
		}
	}
}

// TestPayloadBoundRejectsWrongCiphertextLength requires the live payload
// assertion to reject a valid but incorrectly sized ciphertext.
func TestPayloadBoundRejectsWrongCiphertextLength(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_PAYLOAD_LENGTH_CHILD"
	if os.Getenv(child) == "1" {
		cfg, srv := start(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
			if op != "get" || !strings.HasSuffix(r.URL.Path, "/"+KeyID) {
				return false
			}
			// Advertise version 10 while emitting valid version 1 ciphertext.
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(`{"material":{"version":10}}`)); err != nil {
				t.Error("write synthetic key metadata")
			}
			return true
		})
		conformance.Data(t, testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), KeyID)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestPayloadBoundRejectsWrongCiphertextLength$/^payload_bound$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
		!bytes.Contains(out, []byte("ciphertext overhead at material version 10 with 262144 plaintext bytes: got 191, want 192")) {
		t.Fatal("payload-bound probe did not reject the wrong ciphertext length")
	}
}
