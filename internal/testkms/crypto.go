// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type message struct {
	Plaintext  []byte `json:"plaintext,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	KeySpec    string `json:"key-spec,omitempty"`
	Context    []byte `json:"encryption-context,omitempty"`
	BytesCount *int   `json:"bytes-count,omitempty"`
}

func (s *server) crypt(w http.ResponseWriter, id, op string, k *fakeKey, body []byte, atReplica bool) {
	if k.status != "enabled" {
		disabled(w)
		return
	}
	if op == "re-encrypt" {
		s.reencrypt(w, id, k, body, atReplica)
		return
	}
	var in message
	err := json.Unmarshal(body, &in)
	defer clear(in.Plaintext)
	if err != nil {
		var invalidBase64 base64.CorruptInputError
		if op == "decrypt" && errors.As(err, &invalidBase64) {
			problem(w, 400, invalidParameters, "Invalid Request", "ciphertext must be base64")
			return
		}
		plainError(w, 400)
		return
	}
	switch op {
	case "encrypt":
		switch {
		case len(in.Plaintext) == 786432:
			// A nil value suppresses net/http's automatic Content-Type.
			w.Header()["Content-Type"] = nil
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("server error")); err != nil {
				return // The client disconnected.
			}
		case len(in.Plaintext) > 524288:
			// Keep unprobed larger sizes outside the measured fixture.
			w.WriteHeader(http.StatusNotImplemented)
		default:
			s.encrypt(w, id, k, in.Plaintext, in.Context, false, atReplica)
		}
	case "decrypt":
		raw, err := unwrap(id, k.version, s.extraPadding, in.Ciphertext, in.Context)
		if err != nil {
			reportCiphertextError(w, err)
			return
		}
		defer clear(raw)
		wireJSON(w, 200, message{Plaintext: raw})
	case "generate-data-key":
		length := generationLength(w, in)
		if length == 0 {
			return
		}
		raw := make([]byte, length)
		defer clear(raw)
		if _, err := rand.Read(raw); err != nil {
			plainError(w, 500)
			return
		}
		s.encrypt(w, id, k, raw, in.Context, true, atReplica)
	}
}

const invalidParameters = "#/http-problem-types/request-invalid-parameters"

func generationLength(w http.ResponseWriter, in message) int {
	if (in.KeySpec == "") == (in.BytesCount == nil) {
		detail := "either key-spec or bytes-count must be provided"
		if in.KeySpec != "" {
			detail = "key-spec and bytes-count are mutually exclusive"
		}
		problem(w, 400, invalidParameters, "Invalid argument", detail)
		return 0
	}
	if in.KeySpec == "AES-256" {
		return 32
	}
	if in.BytesCount == nil {
		plainError(w, 400) // Unknown key-spec response is unmeasured.
		return 0
	}
	if *in.BytesCount < 1 || *in.BytesCount > 1024 {
		problem(w, 400, invalidParameters, "Invalid Request", "bytes-count must be between 1 and 1024")
		return 0
	}
	return *in.BytesCount
}

func (s *server) reencrypt(w http.ResponseWriter, id string, source *fakeKey, body []byte, atReplica bool) {
	var in struct {
		Source struct {
			Key        string `json:"key"`
			Ciphertext []byte `json:"ciphertext"`
			Context    []byte `json:"encryption-context"`
		} `json:"source"`
		Destination struct {
			Key     string `json:"key"`
			Context []byte `json:"encryption-context"`
		} `json:"destination"`
	}
	if json.Unmarshal(body, &in) != nil || id != in.Source.Key {
		plainError(w, 400)
		return
	}
	dest := s.keys[in.Destination.Key]
	if dest == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if dest.status != "enabled" {
		disabled(w)
		return
	}
	raw, err := unwrap(id, source.version, s.extraPadding, in.Source.Ciphertext, in.Source.Context)
	if err != nil {
		reportCiphertextError(w, err)
		return
	}
	defer clear(raw)
	s.encrypt(w, in.Destination.Key, dest, raw, in.Destination.Context, false, atReplica)
}

func (s *server) encrypt(w http.ResponseWriter, id string, k *fakeKey, plaintext, aad []byte, includePlaintext, atReplica bool) {
	wrapped, err := wrap(id, k.version, s.extraPadding, plaintext, aad, atReplica)
	if err != nil {
		plainError(w, 500)
		return
	}
	out := message{Ciphertext: wrapped}
	if includePlaintext {
		out.Plaintext = plaintext
	}
	wireJSON(w, 200, out)
}

const (
	// Only the statistical shape is modelled. The framing is test-only.
	wirePrefix        = "fake-kms!"
	nonceSize         = 12
	idSize            = 8
	padSize           = 142
	headerSize        = len(wirePrefix) + nonceSize + idSize + 4
	replicaBit uint32 = 1 << 31
)

var (
	errCiphertext = errors.New("invalid fake ciphertext")
	errOtherKey   = errors.New("ciphertext was encrypted by another fake key")
)

func reportCiphertextError(w http.ResponseWriter, err error) {
	if errors.Is(err, errOtherKey) {
		problem(w, 400, "", "", "Invalid ciphertext: no details. ERN identifiers do not match request")
		return
	}
	problem(w, 400, "#/crypto/invalid-ciphertext", "Invalid ciphertext", "ciphertext validation failed")
}

func wrap(id string, version uint32, extra int, plaintext, aad []byte, atReplica bool) ([]byte, error) {
	padding, err := paddingSize(version, atReplica)
	if err != nil {
		return nil, err
	}
	material := version
	if atReplica {
		material |= replicaBit
	}
	gcm, err := newGCM(id, material)
	if err != nil {
		return nil, err
	}
	prefix := append([]byte(wirePrefix), make([]byte, nonceSize)...)
	if _, err := rand.Read(prefix[len(wirePrefix):]); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(id))
	prefix = append(prefix, digest[:idSize]...)
	prefix = binary.BigEndian.AppendUint32(prefix, material)
	padding += extra
	padded := append(make([]byte, padding, padding+len(plaintext)), plaintext...)
	defer clear(padded)
	return gcm.Seal(prefix, prefix[len(wirePrefix):len(wirePrefix)+nonceSize], padded, aad), nil
}

func unwrap(id string, currentVersion uint32, extra int, blob, aad []byte) ([]byte, error) {
	if len(blob) < headerSize+16 || !bytes.HasPrefix(blob, []byte(wirePrefix)) {
		return nil, errCiphertext
	}
	digest := sha256.Sum256([]byte(id))
	if !bytes.Equal(blob[len(wirePrefix)+nonceSize:headerSize-4], digest[:idSize]) {
		return nil, errOtherKey
	}
	material := binary.BigEndian.Uint32(blob[headerSize-4 : headerSize])
	version := material &^ replicaBit
	if version > currentVersion {
		return nil, errCiphertext
	}
	padding, err := paddingSize(version, material&replicaBit != 0)
	if err != nil {
		return nil, err
	}
	padding += extra
	gcm, err := newGCM(id, material)
	if err != nil {
		return nil, err
	}
	raw, err := gcm.Open(nil, blob[len(wirePrefix):len(wirePrefix)+nonceSize], blob[headerSize:], aad)
	if err != nil {
		return nil, errCiphertext
	}
	if len(raw) < padding {
		clear(raw)
		return nil, errCiphertext
	}
	clear(raw[:padding])
	return raw[padding:], nil
}

// paddingSize varies only the fake's length. Its header is private to the fake.
func paddingSize(version uint32, atReplica bool) (int, error) {
	// Model the measured lengths independently of the assertions.
	padding := padSize
	switch {
	case version >= 1 && version <= 9:
	case version >= 10 && version <= 99:
		padding++
	default:
		return 0, errors.New("fake KMS has no overhead for this material version")
	}
	if atReplica {
		padding--
	}
	return padding, nil
}

func newGCM(id string, version uint32) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(fmt.Sprintf("test-only/%s/%d", id, version)))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
