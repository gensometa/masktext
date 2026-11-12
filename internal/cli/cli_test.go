package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := Run(args, strings.NewReader("alice@example.com\r\n"), &out, &err, "test")
	return code, out.String(), err.String()
}

func TestStreams(t *testing.T) {
	code, out, _ := run()
	if code != 0 || out != "[REDACTED_EMAIL]\r\n" {
		t.Fatalf("%d %q", code, out)
	}
	code, out, _ = run("-t", "password=demo")
	if code != 0 || out != "password=[REDACTED_SECRET]" {
		t.Fatalf("%d %q", code, out)
	}
	code, out, _ = run("--check")
	if code != 1 || out != "" {
		t.Fatal("check leaked output or wrong status")
	}
	code, _, _ = run("-f", "x", "-t", "x")
	if code != 2 {
		t.Fatal("conflict accepted")
	}
	code, out, _ = run("-t", "")
	if code != 0 || out != "" {
		t.Fatal("empty text rejected")
	}
	code, _, _ = run("--check", "-o", "x")
	if code != 2 {
		t.Fatal("check output accepted")
	}
}

func TestFileSafety(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "data.txt")
	dst := filepath.Join(dir, "data.masked.txt")
	os.WriteFile(src, []byte("alice@example.com"), 0644)
	if code, _, err := run("-f", src); code != 0 {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dst)
	if string(b) != "[REDACTED_EMAIL]" {
		t.Fatal(string(b))
	}
	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0600 {
		t.Fatal("output is not private")
	}
	if code, _, _ := run("-f", src); code != 2 {
		t.Fatal("overwrote existing output")
	}
	if code, _, err := run("-f", src, "--force"); code != 0 {
		t.Fatal(err)
	}
	for _, target := range []string{src, filepath.Join(dir, "hard"), filepath.Join(dir, "sym")} {
		if strings.HasSuffix(target, "hard") {
			os.Link(src, target)
		}
		if strings.HasSuffix(target, "sym") {
			os.Symlink(src, target)
		}
		if code, _, _ := run("-f", src, "-o", target, "--force"); code != 2 {
			t.Fatal("input alias accepted")
		}
	}
	b, _ = os.ReadFile(src)
	if string(b) != "alice@example.com" {
		t.Fatal("source modified")
	}
	if code, out, _ := run("-f", src, "-o", "-"); code != 0 || out != "[REDACTED_EMAIL]" {
		t.Fatal("stdout override failed")
	}
}

func TestBadInputs(t *testing.T) {
	for _, s := range []string{"\x00binary", "\xff", strings.Repeat("x", maxBytes+1)} {
		var out, err bytes.Buffer
		if code := Run(nil, strings.NewReader(s), &out, &err, "test"); code != 2 || out.Len() != 0 {
			t.Fatal("invalid input emitted")
		}
	}
}
