// SPDX-License-Identifier: MPL-2.0

// Package conformance shares wire assertions between live and offline KMS tests.
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	egoscale "github.com/exoscale/egoscale/v3"
)

// Client issues signed wire probes. Each HTTP attempt has a deadline.
type Client struct {
	HTTP                     *http.Client
	Endpoint, APIKey, Secret string
	Unanswered               *Unanswered
	blocked                  map[string]bool
}

type request struct {
	Plaintext  []byte `json:"plaintext,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Context    []byte `json:"encryption-context,omitempty"`
	KeySpec    string `json:"key-spec,omitempty"`
	BytesCount *int   `json:"bytes-count,omitempty"`
}

type reencryptRequest struct {
	Source struct {
		Key        string `json:"key"`
		Ciphertext []byte `json:"ciphertext"`
	} `json:"source"`
	Destination struct {
		Key string `json:"key"`
	} `json:"destination"`
}

type result struct {
	code           int
	contentType    string
	hasContentType bool
	raw            []byte
	readback       *reply
	connected      bool
}

type revisionStamp struct {
	At  time.Time `json:"at"`
	Seq int       `json:"seq"`
}

type reply struct {
	Plaintext  []byte         `json:"plaintext"`
	Ciphertext []byte         `json:"ciphertext"`
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	MultiZone  *bool          `json:"multi-zone"`
	DeleteAt   *time.Time     `json:"delete-at"`
	Usage      string         `json:"usage"`
	Revision   *revisionStamp `json:"revision"`
	Replicas   []string       `json:"replicas"`
	KeyType    string         `json:"type"`
	Material   struct {
		Version int `json:"version"`
	} `json:"material"`
	Rotation struct {
		ManualCount int `json:"manual-count"`
	} `json:"rotation"`
	Rotations []struct {
		Version   int  `json:"version"`
		Automatic bool `json:"automatic"`
	} `json:"rotations"`
}

// The fourth unanswered or incomplete attempt is the last within a run's allowance.
const unansweredLimit = 4

// Unanswered counts unanswered and incomplete attempts across clients in one test run.
type Unanswered struct {
	count atomic.Int32
	t     *testing.T
}

// TrackUnanswered logs each missed answer and enforces the run's allowance after cleanup.
func TrackUnanswered(t *testing.T) *Unanswered {
	t.Helper()
	u := &Unanswered{t: t}
	t.Cleanup(func() {
		if n := u.count.Load(); n > unansweredLimit {
			t.Errorf("KMS unanswered budget exceeded: count=%d limit=%d", n, unansweredLimit)
		}
	})
	return u
}

var (
	errUnanswered = errors.New("KMS request unanswered")
	errIncomplete = errors.New("KMS response incomplete")
)

func responseInterrupted(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func responseMissing(err error) bool {
	return errors.Is(err, errUnanswered) || errors.Is(err, errIncomplete)
}

func (c Client) recordInterrupted(kind string) {
	if u := c.Unanswered; u != nil {
		u.t.Logf("KMS %s count=%d limit=%d", kind, u.count.Add(1), unansweredLimit)
	}
}

func (c Client) withinAllowance() bool {
	return c.Unanswered == nil || c.Unanswered.count.Load() <= unansweredLimit
}

func (c Client) call(ctx context.Context, method, path string, body []byte) (result, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var connected, firstByte atomic.Bool
	trace := &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { connected.Store(true) },
		GotFirstResponseByte: func() { firstByte.Store(true) },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, c.Endpoint+"/kms-key"+path, bytes.NewReader(body))
	if err != nil {
		return result{}, errors.New("prepare KMS probe")
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	if egoscale.SignHTTPRequest(req, c.APIKey, c.Secret, time.Now().Add(time.Minute)) != nil {
		return result{}, errors.New("sign KMS probe")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		if responseInterrupted(err) {
			if firstByte.Load() {
				c.recordInterrupted("incomplete_responses")
				return result{connected: true}, errIncomplete
			}
			c.recordInterrupted("unanswered_requests")
			return result{connected: connected.Load()}, errUnanswered
		}
		return result{}, errors.New("KMS probe transport failed")
	}
	defer resp.Body.Close() // All response bytes used by the probe are read below.
	_, hasContentType := resp.Header["Content-Type"]
	got := result{
		code: resp.StatusCode, contentType: resp.Header.Get("Content-Type"),
		hasContentType: hasContentType, connected: true,
	}
	const limit = 2 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case responseInterrupted(err):
		clear(raw)
		c.recordInterrupted("incomplete_responses")
		return got, fmt.Errorf("%w (HTTP %d)", errIncomplete, got.code)
	case err != nil || len(raw) > limit:
		clear(raw)
		return got, fmt.Errorf("KMS probe response unreadable or oversized (HTTP %d)", got.code)
	}
	got.raw = raw
	return got, nil
}

func (c Client) probe(ctx context.Context, method, path string, body []byte) (result, error) {
	got, err := c.call(ctx, method, path, body)
	if responseMissing(err) && ctx.Err() == nil && c.withinAllowance() && replayableProbe(method, path) {
		return c.call(ctx, method, path, body)
	}
	return got, err
}

func replayableProbe(method, path string) bool {
	if method == http.MethodGet {
		return true
	}
	operation := path[strings.LastIndex(path, "/")+1:]
	switch operation {
	case "encrypt", "decrypt", "generate-data-key", "re-encrypt":
		return method == http.MethodPost
	default:
		return false
	}
}

func send[T any](t *testing.T, c Client, method, path string, value T) result {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode conformance request")
	}
	defer clear(raw)
	return sendRaw(t, c, method, path, raw)
}

func sendRaw(t *testing.T, c Client, method, path string, raw []byte) result {
	t.Helper()
	got, err := c.probe(t.Context(), method, path, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(got.raw) })
	return got
}

func success(t *testing.T, got result) reply {
	t.Helper()
	if got.readback != nil {
		return *got.readback
	}
	var out reply
	if got.code != http.StatusOK || json.Unmarshal(got.raw, &out) != nil {
		t.Fatalf("expected HTTP 200 with JSON (got HTTP %d)", got.code)
	}
	t.Cleanup(func() { clear(out.Plaintext); clear(out.Ciphertext) })
	return out
}

type expectation struct {
	code       int
	typ, title string
	encoding   string
}

const (
	invalidCiphertext = "#/crypto/invalid-ciphertext"
	disabledKey       = "#/kms-key/key-disabled"
	singleZone        = "#/kms-key/multi-zone/key-is-not-multi-zone"
	invalidArgument   = "#/http-problem-types/request-invalid-parameters"
	unknownKey        = "#/kms-key/not-found"
	refusalJSON       = "application/json; charset=utf-8"
)

func refusal(t *testing.T, got result, want expectation) {
	t.Helper()
	if got.code != want.code {
		t.Fatalf("expected HTTP %d, got HTTP %d", want.code, got.code)
	}
	if want.typ != "" {
		var problem struct {
			Type, Title string
			Status      int
		}
		if json.Unmarshal(got.raw, &problem) != nil || problem.Status != want.code {
			t.Fatal("expected Problem Details with matching HTTP status")
		}
		if problem.Type != want.typ || problem.Title != want.title {
			t.Fatal("KMS problem type or title differs from the measurement")
		}
	}
	switch want.encoding {
	case "problem":
		if got.contentType != refusalJSON {
			t.Fatal("KMS Problem Details Content-Type differs from the measurement")
		}
	case "signature", "api key", "malformed ID":
		assertMessage(t, got, want.encoding)
	}
}

func assertMessage(t *testing.T, got result, shape string) {
	t.Helper()
	var body struct {
		Message string `json:"message"`
		Errors  []struct {
			Message string   `json:"message"`
			Path    string   `json:"path"`
			In      []string `json:"in"`
		} `json:"errors"`
	}
	if got.contentType != refusalJSON || json.Unmarshal(got.raw, &body) != nil {
		t.Fatal("expected the measured JSON message response")
	}
	switch shape {
	case "signature":
		if body.Message == "Invalid request signature" && len(body.Errors) == 0 {
			return
		}
	case "api key":
		if body.Message == "Invalid key or request signature" && len(body.Errors) == 0 {
			return
		}
	case "malformed ID":
		if body.Message == "Invalid value `not-a-uuid` at 'id': should be a UUID" && len(body.Errors) == 1 {
			field := body.Errors[0]
			if field.Message == "should be a UUID" && field.Path == "id" && len(field.In) == 1 && field.In[0] == "id" {
				return
			}
		}
	}
	t.Fatal("KMS error message differs from the measurement")
}

func post(t *testing.T, c Client, id, op string, in request) result {
	t.Helper()
	return send(t, c, http.MethodPost, "/"+id+"/"+op, in)
}

func enc(t *testing.T, c Client, id string, plaintext, aad []byte) []byte {
	t.Helper()
	return success(t, post(t, c, id, "encrypt", request{Plaintext: plaintext, Context: aad})).Ciphertext
}

func dec(t *testing.T, c Client, id string, ciphertext, aad, want []byte) {
	t.Helper()
	out := success(t, post(t, c, id, "decrypt", request{Ciphertext: ciphertext, Context: aad}))
	if !bytes.Equal(out.Plaintext, want) {
		t.Fatal("decrypt must recover the original bytes")
	}
}
