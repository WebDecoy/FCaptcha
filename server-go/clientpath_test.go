package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for #23: the Docker image copies the widget to
// /app/static/fcaptcha.js, but resolveClientPath only probed client/ paths, so
// /fcaptcha.js returned 404 in every published image — and the demo page the
// image ships loads the widget from that path, so it never initialised either.

func TestResolveClientPathFindsDockerLayout(t *testing.T) {
	// Reproduce the image: a binary in /app with the widget at ./static/.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "static", "fcaptcha.js")
	if err := os.WriteFile(want, []byte("// widget"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(dir)
	t.Setenv("FCAPTCHA_CLIENT_PATH", "")

	got := resolveClientPath()
	if got == "" {
		t.Fatal("the Docker image's static/ layout was not found — /fcaptcha.js would 404")
	}
	if !strings.HasSuffix(got, filepath.Join("static", "fcaptcha.js")) {
		t.Errorf("resolved %q, expected the static/ copy", got)
	}
}

func TestResolveClientPathFindsRepoLayout(t *testing.T) {
	// `go run .` from server-go/, i.e. the widget one level up.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "client"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client", "fcaptcha.js"), []byte("// widget"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "server-go")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Chdir(sub)
	t.Setenv("FCAPTCHA_CLIENT_PATH", "")

	if got := resolveClientPath(); got == "" {
		t.Error("the repo layout (../client/fcaptcha.js) was not found")
	}
}

func TestResolveClientPathEnvOverrideWins(t *testing.T) {
	t.Setenv("FCAPTCHA_CLIENT_PATH", "/somewhere/else/fcaptcha.js")
	if got := resolveClientPath(); got != "/somewhere/else/fcaptcha.js" {
		t.Errorf("the explicit override must win, got %q", got)
	}
}

// The unit tests above cannot catch a Dockerfile that moves the file somewhere
// new. That is what the docker-smoke CI job is for — it builds the image and
// fetches /fcaptcha.js. This test records the coupling so anyone editing the
// candidate list knows the Dockerfile is the other half of it.
func TestCandidateListCoversDockerfileDestination(t *testing.T) {
	df, err := os.ReadFile(filepath.Join("..", "docker", "Dockerfile"))
	if err != nil {
		t.Skipf("docker/Dockerfile not readable from here: %v", err)
	}
	if !strings.Contains(string(df), "./static/fcaptcha.js") {
		t.Fatal("docker/Dockerfile no longer copies the widget to ./static/fcaptcha.js — " +
			"update resolveClientPath's candidate list to match, or /fcaptcha.js will 404 (see #23)")
	}
}
