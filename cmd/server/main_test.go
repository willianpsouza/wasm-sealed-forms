package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouterRoutes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "<!doctype html><title>t</title>")
	write("app.wasm", "\x00asm")

	srv := httptest.NewServer(newRouter(dir))
	defer srv.Close()

	cases := []struct {
		path       string
		wantStatus int
		wantCTHas  string
	}{
		{"/", http.StatusOK, "text/html"},
		{"/app.wasm", http.StatusOK, "application/wasm"},
		{"/api/health", http.StatusOK, "text/plain"},
	}
	for _, c := range cases {
		resp, err := http.Get(srv.URL + c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if resp.StatusCode != c.wantStatus {
			t.Errorf("%s: status %d want %d", c.path, resp.StatusCode, c.wantStatus)
		}
		if ct := resp.Header.Get("Content-Type"); c.wantCTHas != "" && !strings.Contains(ct, c.wantCTHas) {
			t.Errorf("%s: content-type %q missing %q", c.path, ct, c.wantCTHas)
		}
		resp.Body.Close()
	}
}

func TestEnv(t *testing.T) {
	if got := env("SF_NONEXISTENT", "fallback"); got != "fallback" {
		t.Errorf("env fallback = %q", got)
	}
	t.Setenv("SF_SET", "value")
	if got := env("SF_SET", "fallback"); got != "value" {
		t.Errorf("env value = %q", got)
	}
}
