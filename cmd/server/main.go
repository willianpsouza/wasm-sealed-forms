// Command server serves the PII form SPA, the WASM artifact, and a
// /api/submit endpoint that decrypts + verifies the sealed form.
//
// The point of the demo: the form is sealed in the browser, so a TLS-terminating
// intermediary (API gateway, reverse proxy, CDN, WAF) only ever sees ciphertext.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	staticDir := env("STATIC_DIR", "web/static")
	addr := env("ADDR", ":8097")

	log.Printf("serving %s on %s", staticDir, addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           newRouter(staticDir),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// newRouter wires the SPA, the WASM artifact, and the submit API.
func newRouter(staticDir string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Post("/api/submit", handleSubmit)
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	fs := http.FileServer(http.Dir(staticDir))
	r.Handle("/*", wasmContentType(fs))
	return r
}

// wasmContentType serves .wasm as application/wasm for streaming compilation.
func wasmContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.URL.Path) > 5 && req.URL.Path[len(req.URL.Path)-5:] == ".wasm" {
			w.Header().Set("Content-Type", "application/wasm")
		}
		next.ServeHTTP(w, req)
	})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
