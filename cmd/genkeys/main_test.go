package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArrFormatters(t *testing.T) {
	if got := rustArr([]byte{0x00, 0xab, 0xff}); got != "[0x00, 0xab, 0xff]" {
		t.Errorf("rustArr = %q", got)
	}
	if got := goArr([]byte{0x01, 0x02}); got != "{0x01, 0x02}" {
		t.Errorf("goArr = %q", got)
	}
}

func TestGeneratesBothFiles(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"web/wasm/src", "cmd/server"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldArgs := os.Args
	os.Args = []string{"genkeys", root}
	defer func() { os.Args = oldArgs }()
	main()

	rs, err := os.ReadFile(filepath.Join(root, "web", "wasm", "src", "keys_gen.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rs), "ED25519_SEED") || !strings.Contains(string(rs), "SERVER_X25519_PUB") {
		t.Error("keys_gen.rs missing constants")
	}
	gs, err := os.ReadFile(filepath.Join(root, "cmd", "server", "keys_gen.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gs), "ed25519Pub") || !strings.Contains(string(gs), "x25519Secret") {
		t.Error("keys_gen.go missing variables")
	}
}
