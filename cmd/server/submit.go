package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	maxBody   = 1 << 20 // 1 MB is plenty for a form
	hkdfInfo  = "wasm-sealed-forms-v1"
	ephLen    = 32
	nonceLen  = 24
	minEnvLen = ephLen + nonceLen + 16
)

// Fields an insurance submission must contain. We only ever check for the
// PRESENCE of these keys — values are never read into the response or logs.
var requiredFields = []string{"full_name", "cpf", "birth_date", "address", "bank_account"}

type submitRequest struct {
	Payload string `json:"payload"` // base64 envelope
}

type sealedInner struct {
	BodyB64 string `json:"body_b64"`
	SigB64  string `json:"sig_b64"`
}

// submitResponse carries NO PII — only metadata the backend is willing to
// expose about an accepted submission.
type submitResponse struct {
	Received     bool     `json:"received"`
	SignatureOK  bool     `json:"signature_ok"`
	SubmissionID string   `json:"submission_id,omitempty"`
	FieldCount   int      `json:"field_count,omitempty"`
	Present      []string `json:"present,omitempty"`
	Missing      []string `json:"missing,omitempty"`
	Error        string   `json:"error,omitempty"`
}

func handleSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "read body: " + err.Error()})
		return
	}
	var req submitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "bad json: " + err.Error()})
		return
	}
	envelope, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "bad base64: " + err.Error()})
		return
	}

	plaintext, err := unseal(envelope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "unseal: " + err.Error()})
		return
	}

	var inner sealedInner
	if err := json.Unmarshal(plaintext, &inner); err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "inner json: " + err.Error()})
		return
	}
	formBytes, err := base64.StdEncoding.DecodeString(inner.BodyB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "body b64: " + err.Error()})
		return
	}
	sig, err := base64.StdEncoding.DecodeString(inner.SigB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Error: "sig b64: " + err.Error()})
		return
	}

	sigOK := ed25519.Verify(ed25519Pub, formBytes, sig)

	// Inspect keys only — never read PII values into the response.
	var form map[string]json.RawMessage
	if err := json.Unmarshal(formBytes, &form); err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{
			Received: true, SignatureOK: sigOK, Error: "form not a JSON object: " + err.Error(),
		})
		return
	}
	present, missing := checkFields(form)

	// A real backend would persist the decrypted PII here, inside the trust
	// boundary. The demo just acknowledges with non-PII metadata.
	writeJSON(w, http.StatusOK, submitResponse{
		Received:     true,
		SignatureOK:  sigOK,
		SubmissionID: newID(),
		FieldCount:   len(form),
		Present:      present,
		Missing:      missing,
	})
}

func checkFields(form map[string]json.RawMessage) (present, missing []string) {
	for _, f := range requiredFields {
		if _, ok := form[f]; ok {
			present = append(present, f)
		} else {
			missing = append(missing, f)
		}
	}
	sort.Strings(present)
	sort.Strings(missing)
	return present, missing
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// unseal reverses seal_to_backend in the WASM module:
// envelope = ephemeral_pub(32) || nonce(24) || ciphertext
func unseal(envelope []byte) ([]byte, error) {
	if len(envelope) < minEnvLen {
		return nil, errors.New("envelope too short")
	}
	ephPub := envelope[:ephLen]
	nonce := envelope[ephLen : ephLen+nonceLen]
	ct := envelope[ephLen+nonceLen:]

	shared, err := curve25519.X25519(x25519Secret, ephPub)
	if err != nil {
		return nil, err
	}
	hk := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, ephPub)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
