package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// sealInGo mirrors the WASM module's seal_to_backend.
func sealInGo(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	serverPub, err := curve25519.X25519(x25519Secret, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	ephSec := make([]byte, 32)
	if _, err := rand.Read(ephSec); err != nil {
		t.Fatal(err)
	}
	ephPub, err := curve25519.X25519(ephSec, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(ephSec, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	hk := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, nonce, plaintext, ephPub)
	env := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	env = append(env, ephPub...)
	env = append(env, nonce...)
	env = append(env, ct...)
	return env
}

func post(t *testing.T, body string) (*submitResponse, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleSubmit(w, req)
	raw := w.Body.String()
	var resp submitResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, raw)
	}
	return &resp, raw
}

// sealForm signs `formJSON` with `priv` and seals it as the WASM module would.
func sealForm(t *testing.T, priv ed25519.PrivateKey, formJSON string) string {
	sig := ed25519.Sign(priv, []byte(formJSON))
	inner := sealedInner{
		BodyB64: base64.StdEncoding.EncodeToString([]byte(formJSON)),
		SigB64:  base64.StdEncoding.EncodeToString(sig),
	}
	innerJSON, _ := json.Marshal(inner)
	env := sealInGo(t, innerJSON)
	reqBody, _ := json.Marshal(submitRequest{Payload: base64.StdEncoding.EncodeToString(env)})
	return string(reqBody)
}

func withTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	orig := ed25519Pub
	ed25519Pub = pub
	t.Cleanup(func() { ed25519Pub = orig })
	return priv
}

func TestUnsealRoundTrip(t *testing.T) {
	msg := []byte("roundtrip payload")
	out, err := unseal(sealInGo(t, msg))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(msg) {
		t.Fatalf("got %q want %q", out, msg)
	}
}

func TestUnsealTooShort(t *testing.T) {
	if _, err := unseal([]byte("short")); err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitHappyPathNoPIILeak(t *testing.T) {
	priv := withTestKey(t)
	form := `{"full_name":"Ana Silva","cpf":"000.000.000-00","birth_date":"1990-01-01","address":"Rua X 123","bank_account":"1234-5","children":2}`

	resp, raw := post(t, sealForm(t, priv, form))
	if !resp.Received || !resp.SignatureOK {
		t.Fatalf("received=%v sig=%v err=%q", resp.Received, resp.SignatureOK, resp.Error)
	}
	if resp.FieldCount != 6 {
		t.Errorf("field_count = %d want 6", resp.FieldCount)
	}
	if len(resp.Missing) != 0 {
		t.Errorf("missing = %v want none", resp.Missing)
	}
	if len(resp.Present) != len(requiredFields) {
		t.Errorf("present = %v", resp.Present)
	}
	if resp.SubmissionID == "" {
		t.Error("expected submission id")
	}
	// the response must NOT contain any PII value
	for _, pii := range []string{"Ana Silva", "000.000.000-00", "Rua X", "1234-5", "1990-01-01"} {
		if strings.Contains(raw, pii) {
			t.Errorf("PII leaked in response: %q", pii)
		}
	}
	// the backend-recomputed digest must match sha256(form)
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(form)))
	if resp.Digest != want {
		t.Errorf("digest = %q want %q", resp.Digest, want)
	}
}

func TestSubmitGenericErrorNoLeak(t *testing.T) {
	priv := withTestKey(t)
	// build a valid request, then corrupt the ciphertext so AEAD open fails
	good := sealForm(t, priv, `{"full_name":"X","cpf":"1","birth_date":"1","address":"a","bank_account":"b"}`)
	var req submitRequest
	_ = json.Unmarshal([]byte(good), &req)
	env, _ := base64.StdEncoding.DecodeString(req.Payload)
	env[len(env)-1] ^= 0xff // flip a ciphertext byte
	bad, _ := json.Marshal(submitRequest{Payload: base64.StdEncoding.EncodeToString(env)})

	resp, raw := post(t, string(bad))
	if resp.Received {
		t.Error("should not be received")
	}
	if resp.Error != errCannotProcess {
		t.Errorf("error = %q want generic %q", resp.Error, errCannotProcess)
	}
	// internal detail must never reach the client
	for _, leak := range []string{"chacha20poly1305", "authentication failed", "unseal", "aead"} {
		if strings.Contains(strings.ToLower(raw), leak) {
			t.Errorf("internal detail leaked: %q in %q", leak, raw)
		}
	}
}

func TestSubmitBadBase64Generic(t *testing.T) {
	resp, raw := post(t, `{"payload":"!!!"}`)
	if resp.Error != errInvalidRequest {
		t.Errorf("error = %q want %q", resp.Error, errInvalidRequest)
	}
	if strings.Contains(raw, "base64") {
		t.Errorf("leaked base64 detail: %q", raw)
	}
}

func TestSubmitMissingRequiredFields(t *testing.T) {
	priv := withTestKey(t)
	form := `{"full_name":"Bob","address":"somewhere"}`
	resp, _ := post(t, sealForm(t, priv, form))
	if !resp.Received {
		t.Fatal("should be received")
	}
	// cpf, birth_date, bank_account missing
	if len(resp.Missing) != 3 {
		t.Errorf("missing = %v want 3", resp.Missing)
	}
}

func TestSubmitBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader) // server expects THIS pub
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	orig := ed25519Pub
	ed25519Pub = pub
	defer func() { ed25519Pub = orig }()

	resp, _ := post(t, sealForm(t, attacker, `{"full_name":"X","cpf":"1","birth_date":"1","address":"a","bank_account":"b"}`))
	if !resp.Received {
		t.Error("decryption should succeed")
	}
	if resp.SignatureOK {
		t.Error("signature should be invalid (wrong signer)")
	}
}

func TestSubmitNonObjectForm(t *testing.T) {
	priv := withTestKey(t)
	resp, _ := post(t, sealForm(t, priv, `[1,2,3]`))
	if resp.Error == "" {
		t.Error("expected error for non-object form")
	}
}

func TestSubmitBadJSON(t *testing.T) {
	resp, _ := post(t, "{not json")
	if resp.Error == "" {
		t.Error("expected error")
	}
}

func TestSubmitBadBase64(t *testing.T) {
	resp, _ := post(t, `{"payload":"!!!"}`)
	if resp.Error == "" {
		t.Error("expected error")
	}
}

func TestSubmitShortEnvelope(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	resp, _ := post(t, `{"payload":"`+short+`"}`)
	if resp.Received || resp.Error == "" {
		t.Error("expected unseal failure")
	}
}

func TestSubmitBadInnerJSON(t *testing.T) {
	env := sealInGo(t, []byte("not inner json"))
	body, _ := json.Marshal(submitRequest{Payload: base64.StdEncoding.EncodeToString(env)})
	resp, _ := post(t, string(body))
	if resp.Error == "" {
		t.Error("expected inner json error")
	}
}
