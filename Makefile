COVER_MIN ?= 80

.PHONY: test cover cover-go cover-rust cover-docker keys clean

## test: run Go + Rust unit tests (needs keys_gen.* — run `make keys` first)
test:
	go test ./...
	cd web/wasm && cargo test

## keys: generate the git-ignored demo keypair source files
keys:
	go run ./cmd/genkeys .

## cover: run both coverage gates locally (requires Go, Rust, cargo-llvm-cov)
cover: cover-go cover-rust

## cover-go: Go coverage, fails under $(COVER_MIN)%
cover-go:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {sub(/%/,"",$$3); print $$3}'); \
	echo "Go coverage: $$total% (min $(COVER_MIN)%)"; \
	awk -v t=$$total -v m=$(COVER_MIN) 'BEGIN{exit !(t+0 >= m+0)}' || { echo "FAIL: Go coverage below $(COVER_MIN)%"; exit 1; }

## cover-rust: Rust line coverage, fails under $(COVER_MIN)%
cover-rust:
	cd web/wasm && cargo llvm-cov --summary-only --fail-under-lines $(COVER_MIN)

## cover-docker: run the whole coverage gate in containers (no host toolchains)
cover-docker:
	docker compose -f docker-compose.test.yml up --build \
		--abort-on-container-exit --exit-code-from gate

clean:
	rm -f coverage.out
	rm -rf web/wasm/target web/static/pkg
