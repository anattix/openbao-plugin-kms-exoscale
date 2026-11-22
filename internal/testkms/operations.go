// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type fakeKey struct {
	name, status string
	multiZone    bool
	version      uint32
	manualCount  uint32
	replica      string
	revision     int
	deleteAt     *time.Time
}

type keyMetadata struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	MultiZone bool       `json:"multi-zone"`
	Replicas  []string   `json:"replicas,omitempty"`
	Usage     string     `json:"usage"`
	DeleteAt  *time.Time `json:"delete-at,omitempty"`
	Revision  struct {
		At  time.Time `json:"at"`
		Seq int       `json:"seq"`
	} `json:"revision"`
	Material struct {
		Version uint32 `json:"version"`
	} `json:"material"`
	Rotation struct {
		ManualCount uint32 `json:"manual-count"`
	} `json:"rotation"`
}

func (k *fakeKey) metadata(id string) keyMetadata {
	m := keyMetadata{ID: id, Name: k.name, Status: k.status, MultiZone: k.multiZone, Usage: "encrypt-decrypt", DeleteAt: k.deleteAt}
	m.Material.Version, m.Rotation.ManualCount = k.version, k.manualCount
	if k.replica != "" {
		m.Replicas = []string{k.replica}
	}
	m.Revision.Seq = k.revision
	m.Revision.At = time.Unix(int64(k.revision), 0).UTC()
	return m
}

func (s *server) collection(w http.ResponseWriter, op string, body []byte) {
	if op == "list" {
		out := struct {
			Keys []keyMetadata `json:"kms-keys"`
		}{Keys: make([]keyMetadata, 0, len(s.keys))}
		for id, k := range s.keys {
			out.Keys = append(out.Keys, k.metadata(id))
		}
		wireJSON(w, 200, out)
		return
	}
	var in struct {
		Name      string `json:"name"`
		Usage     string `json:"usage"`
		MultiZone bool   `json:"multi-zone"`
	}
	if json.Unmarshal(body, &in) != nil || in.Name == "" || in.Usage != "encrypt-decrypt" {
		plainError(w, 400)
		return
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		plainError(w, 500)
		return
	}
	idBytes[6], idBytes[8] = idBytes[6]&15|64, idBytes[8]&63|128
	id := fmt.Sprintf("%x-%x-%x-%x-%x", idBytes[:4], idBytes[4:6], idBytes[6:8], idBytes[8:10], idBytes[10:])
	k := &fakeKey{name: in.Name, status: "enabled", multiZone: in.MultiZone, version: 1}
	s.keys[id] = k
	wireJSON(w, 200, k.metadata(id))
}

func (s *server) lifecycle(w http.ResponseWriter, id, op string, k *fakeKey, body []byte, atReplica bool) {
	if atReplica && (op == "rotate" || op == "schedule-deletion") {
		problem(w, http.StatusBadRequest, "#/kms-key/multi-zone/operation-not-allowed-on-a-replica", "Operation not allowed on replica", "")
		return
	}
	switch op {
	case "get":
		meta := k.metadata(id)
		if atReplica {
			meta.Replicas = nil
		}
		wireJSON(w, 200, meta)
		return
	case "rotate":
		if k.status != "enabled" {
			disabled(w)
			return
		}
		if k.manualCount >= 10 {
			problem(w, http.StatusBadRequest, "#/kms-key/manual-rotation-limit", "Maximum rotation limit exceeded", "no details.")
			return
		}
		k.version++
		k.manualCount++
	case "list-key-rotations":
		type rotation struct {
			Version   uint32 `json:"version"`
			Automatic bool   `json:"automatic"`
		}
		out := struct {
			Rotations []rotation `json:"rotations"`
		}{}
		for v := uint32(2); v <= k.version; v++ {
			out.Rotations = append(out.Rotations, rotation{Version: v})
		}
		wireJSON(w, 200, out)
		return
	case "replicate":
		if !k.multiZone {
			problem(w, 400, "#/kms-key/multi-zone/key-is-not-multi-zone", "Replication allowed on multi-zone keys only", "no details.")
			return
		}
		var in struct{ Zone string }
		if json.Unmarshal(body, &in) != nil || in.Zone != ReplicaZone {
			plainError(w, 400)
			return
		}
		k.replica = in.Zone
	case "disable":
		k.status = "disabled"
	case "enable":
		k.status = "enabled"
	case "schedule-deletion":
		schedule(w, k, body)
		return
	case "cancel-deletion":
		if k.status != "pending-deletion" {
			plainError(w, 400)
			return
		}
		k.status, k.deleteAt = "disabled", nil
	default:
		plainError(w, 400)
		return
	}
	k.revision++
	wireJSON(w, 200, struct{}{})
}

func schedule(w http.ResponseWriter, k *fakeKey, body []byte) {
	var in struct {
		Days int `json:"delay-days"`
	}
	if json.Unmarshal(body, &in) != nil || in.Days < 7 || in.Days > 30 {
		plainError(w, 400)
		return
	}
	if k.deleteAt == nil {
		when := time.Now().UTC().Add(time.Duration(in.Days) * 24 * time.Hour)
		k.status, k.deleteAt = "pending-deletion", &when
		k.revision++
	}
	wireJSON(w, 200, struct {
		DeleteAt *time.Time `json:"delete-at"`
	}{k.deleteAt})
}

func disabled(w http.ResponseWriter) {
	problem(w, 400, "#/kms-key/key-disabled", "Key is disabled", "")
}

func plainError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

const refusalJSON = "application/json; charset=utf-8"

func problem(w http.ResponseWriter, status int, typ, title, detail string) {
	w.Header().Set("Content-Type", refusalJSON)
	wireJSON(w, status, struct {
		Type   string `json:"type,omitempty"`
		Title  string `json:"title,omitempty"`
		Status int    `json:"status"`
		Detail string `json:"detail,omitempty"`
	}{typ, title, status, detail})
}

func wireJSON[T any](w http.ResponseWriter, status int, out T) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return
	} // The client disconnected.
}
