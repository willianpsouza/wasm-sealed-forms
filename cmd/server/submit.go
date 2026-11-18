package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// Generic, non-leaking client-facing error messages. The real cause is logged
// server-side, never returned, so a tampered envelope does not reveal the
// algorithm or exact failure (e.g. "chacha20poly1305: message authentication
// failed").
const (
	errInvalidRequest = "invalid request"
	errCannotProcess  = "could not process submission"
)

// submitResponse carries NO PII — only metadata the backend is willing to
// expose about an accepted submission.
type submitResponse struct {
	Received bool `json:"received"`
	// SignatureOK is INFORMATIONAL only. It is not an access-control gate (the
	// submit is accepted regardless) and it does not prove who submitted: the
	// Ed25519 key is extractable from the public .wasm, so anyone can forge a
	// valid signature. Keep real auth (session/token/mTLS) server-side.
	SignatureOK  bool     `json:"signature_ok"`
	SubmissionID string   `json:"submission_id,omitempty"`
	FieldCount   int      `json:"field_count,omitempty"`
	Present      []string `json:"present,omitempty"`
	Missing      []string `json:"missing,omitempty"`
	// Digest is sha256(form) recomputed server-side so the client can compare it
	// with its own digest and confirm the round-trip. Integrity is already
	// guaranteed by the AEAD + signature; this is the visible receipt.
	Digest string `json:"digest,omitempty"`
	Error  string `json:"error,omitempty"`
}

// clientError logs the real cause and returns a generic message to the client.
func clientError(w http.ResponseWriter, code int, msg string, internal error) {
	log.Printf("submit: %v", internal)
	writeJSON(w, code, submitResponse{Error: msg})
}

// handleSubmit decrypts and verifies a sealed form submission.
//
// No replay protection: a captured envelope can be resubmitted and will decrypt
// again. For a real system bind each envelope to a server-issued nonce/timestamp
// (as AAD) and reject duplicates. Out of scope for this demo.
func handleSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		clientError(w, http.StatusBadRequest, errInvalidRequest, fmt.Errorf("read body: %w", err))
		return
	}
	var req submitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		clientError(w, http.StatusBadRequest, errInvalidRequest, fmt.Errorf("bad json: %w", err))
		return
	}
	envelope, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		clientError(w, http.StatusBadRequest, errInvalidRequest, fmt.Errorf("bad base64: %w", err))
		return
	}

	plaintext, err := unseal(envelope)
	if err != nil {
		clientError(w, http.StatusBadRequest, errCannotProcess, fmt.Errorf("unseal: %w", err))
		return
	}

	var inner sealedInner
	if err := json.Unmarshal(plaintext, &inner); err != nil {
		clientError(w, http.StatusBadRequest, errCannotProcess, fmt.Errorf("inner json: %w", err))
		return
	}
	formBytes, err := base64.StdEncoding.DecodeString(inner.BodyB64)
	if err != nil {
		clientError(w, http.StatusBadRequest, errCannotProcess, fmt.Errorf("body b64: %w", err))
		return
	}
	sig, err := base64.StdEncoding.DecodeString(inner.SigB64)
	if err != nil {
		clientError(w, http.StatusBadRequest, errCannotProcess, fmt.Errorf("sig b64: %w", err))
		return
	}

	// Informational only — NOT an access-control gate and NOT proof of origin
	// (the signing key is extractable from the public .wasm). See SignatureOK.
	sigOK := ed25519.Verify(ed25519Pub, formBytes, sig)

	// Inspect keys only — never read PII values into the response.
	var form map[string]json.RawMessage
	if err := json.Unmarshal(formBytes, &form); err != nil {
		log.Printf("submit: form not a JSON object: %v", err)
		writeJSON(w, http.StatusBadRequest, submitResponse{
			Received: true, SignatureOK: sigOK, Error: errCannotProcess,
		})
		return
	}
	present, missing := checkFields(form)

	// sha256(form) recomputed inside the trust boundary as a visible receipt.
	digest := fmt.Sprintf("%x", sha256.Sum256(formBytes))

	// A real backend would persist the decrypted PII here, inside the trust
	// boundary. The demo just acknowledges with non-PII metadata.
	writeJSON(w, http.StatusOK, submitResponse{
		Received:     true,
		SignatureOK:  sigOK,
		SubmissionID: newID(),
		FieldCount:   len(form),
		Present:      present,
		Missing:      missing,
		Digest:       digest,
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
