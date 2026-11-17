# syntax=docker/dockerfile:1

# ---------- Stage 1: generate the demo keypairs + source files ----------
FROM golang:1.26 AS keygen
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
RUN go mod tidy
RUN mkdir -p web/wasm/src cmd/server && go run ./cmd/genkeys .

# ---------- Stage 2: build the Rust -> WASM artifact ----------
FROM rust:1-bookworm AS wasm
# Build wasm-bindgen-cli from source so it matches the host glibc; version must
# match the wasm-bindgen crate pinned in Cargo.toml.
RUN cargo install wasm-bindgen-cli --version 0.2.100 --locked
RUN rustup target add wasm32-unknown-unknown
WORKDIR /wasm
COPY web/wasm/ ./
COPY --from=keygen /src/web/wasm/src/keys_gen.rs ./src/keys_gen.rs
RUN cargo build --release --target wasm32-unknown-unknown
RUN wasm-bindgen target/wasm32-unknown-unknown/release/wasm_sealed_forms.wasm \
        --out-dir pkg --target web

# ---------- Stage 3: build the Go server ----------
FROM golang:1.26 AS server
WORKDIR /src
COPY . .
COPY --from=keygen /src/go.sum ./go.sum
COPY --from=keygen /src/cmd/server/keys_gen.go ./cmd/server/keys_gen.go
RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server

# ---------- Final: minimal runtime ----------
FROM gcr.io/distroless/base-debian12
COPY --from=server /out/server /server
COPY web/static/ /web/static/
COPY --from=wasm /wasm/pkg/ /web/static/pkg/
ENV STATIC_DIR=/web/static ADDR=:8097
EXPOSE 8097
ENTRYPOINT ["/server"]
