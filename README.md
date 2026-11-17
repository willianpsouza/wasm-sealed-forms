# WASM Sealed PII Form

> [Versão em português](README.pt-BR.md)

Example repo: a PII-heavy form (think insurance signup — name, CPF, address,
bank account, date of birth, children, workplace) is **signed and sealed in the
browser with Rust/WebAssembly** before it is sent. Only the backend can decrypt
it. Every intermediary on the path sees ciphertext.

Same crypto technique as the [file-validator demo](https://github.com/willianpsouza/wasm-file-validator),
applied to confidentiality of form data instead of file verdicts.

## The problem

HTTPS protects data **in transit**, but TLS is usually **terminated before** the
application: at a load balancer, API gateway, reverse proxy, CDN, or WAF. After
termination the request body is plaintext, and any of those hops — plus their
access logs and any tap on the internal network — can read every PII field.

```
browser ──TLS──▶ [ API gateway / reverse proxy / CDN / WAF ] ──▶ backend
                         ▲ TLS ends here: sees PLAINTEXT PII
```

## The technique

Seal the body **end-to-end** in the browser, to a key only the backend holds:

```
browser                                   intermediaries        backend
┌───────────────────────────┐             (gateway/proxy)       ┌──────────────┐
│ form JSON                  │                                  │ x25519 secret│
│  ├─ sign (Ed25519)         │   ciphertext only, unreadable    │ decrypt      │
│  └─ seal (x25519 + XChaCha)│ ───────────────────────────────▶ │ verify sig   │
│      → base64 envelope      │                                  │ parse PII    │
└───────────────────────────┘                                  └──────────────┘
```

- `GET /` — the form SPA
- `GET /pkg/*` — the compiled WASM artifact + JS glue
- `POST /api/submit` — decrypts the envelope, verifies the signature, parses the
  PII **inside the trust boundary**, and replies with non-PII metadata only
  (submission id, field count, which required fields were present/missing).

A bonus the request mentions: the public API exposes **no readable schema** — the
endpoint consumes opaque sealed blobs. That raises the cost of casually scraping
or fuzzing the API. It is defense-in-depth, not a security guarantee on its own.

## Threat model — what this does and does NOT do

**Protects against** (the goal): a passive or honest-but-curious intermediary
between the browser and the backend — API gateway, reverse proxy, CDN, WAF,
request/access logs, internal network taps — reading the user's PII. They only
ever see the sealed envelope.

**Does NOT protect against:**

- **A compromised origin.** The server that ships the WASM could ship a backdoored
  build. End-to-end sealing assumes the delivered client is honest. Use SRI,
  reproducible builds, and code review to constrain this.
- **Submitter authenticity.** The Ed25519 signing key is embedded in the public
  `.wasm` and is extractable, and the x25519 seal uses the backend's *public*
  key — so **anyone** can craft a valid sealed submission. This layer does not
  tell the backend *who* submitted; keep your normal auth (session, token,
  mTLS) and server-side validation.
- **A replacement for TLS.** Keep HTTPS. This is a layer *on top* of it so that
  TLS termination no longer exposes the body.
- **Security by obscurity.** The opaque API raises attacker effort; it is not a
  substitute for authn/authz.

In short: this buys **confidentiality of form data against intermediaries**, and
nothing more. That is exactly the property the demo is about.

## ⚠️ Keys

Because the repo is public, keypairs are generated at build time by `cmd/genkeys`
into git-ignored files (`keys_gen.rs`, `keys_gen.go`) and are **never committed**.
In production the backend's x25519 secret lives only inside the trust boundary
(KMS/HSM/secret store), and you would rotate it.

## Run (Docker)

```bash
docker compose up --build
# open http://localhost:8097
```

Submit the form, then watch: the "what leaves the browser" panel shows only
base64 ciphertext (the proxy's view), while the backend panel shows the parsed
result. Open DevTools → Network on `/api/submit` to confirm no PII is on the wire.

## Build locally (without Docker)

Needs Go ≥1.23, Rust, and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
go mod tidy
go run ./cmd/genkeys .
cd web/wasm && wasm-pack build --release --target web --out-dir ../static/pkg
cd ../..
go run ./cmd/server                    # http://localhost:8097
```

## Tests & coverage

Minimal test stack with an **80% coverage** gate (Go + Rust).

```bash
make keys           # generate keys_gen.* (required before testing)
make test           # Go + Rust unit tests
make cover          # 80% gate for Go and Rust (needs cargo-llvm-cov)
make cover-docker   # run the whole gate in containers, no host toolchains
```

Go tests re-create the seal in-test to exercise `unseal`/`handleSubmit`, assert
the response **leaks no PII**, cover required-field logic, valid/invalid
signatures and malformed input. Rust tests cover sealing, signing, JSON
rejection and the digest helper natively.

## Crypto, precisely

- **Sign:** Ed25519 over the canonical form JSON bytes.
- **Seal:** ephemeral x25519 keypair; `shared = X25519(eph_secret, backend_pub)`;
  `key = HKDF-SHA256(shared, info="wasm-sealed-forms-v1")`;
  `XChaCha20-Poly1305(key, nonce)` with the ephemeral public key as AAD.
- **Envelope:** `ephemeral_pub(32) || nonce(24) || ciphertext`, base64-encoded.

## Layout

```
cmd/genkeys/      generates keypairs + embedded-key source files
cmd/server/       chi server: SPA + wasm + /api/submit
web/wasm/         Rust crate (sign + seal)
web/static/       form SPA; wasm-pack output lands in web/static/pkg/
```

## License

MIT
