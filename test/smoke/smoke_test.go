//go:build smoke

// Package smoke checks a release binary end to end. It is excluded from
// normal test runs; run it against a built artifact:
//
//	ZONELINT_BIN=dist/zonelint go test -tags smoke ./test/smoke
//
// ZONELINT_EXPECT_VERSION, when set, must match the reported version.
package smoke

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var root = filepath.Join("..", "..")

func binary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ZONELINT_BIN")
	if bin == "" {
		t.Fatal("ZONELINT_BIN must point at the binary under test")
	}
	// Relative paths are resolved against the repository root, where the
	// command is normally invoked, not against this package directory.
	if !filepath.IsAbs(bin) {
		bin = filepath.Join(root, bin)
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatal(err)
	}
	return abs
}

func runBinary(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return out.String(), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), 0
}

func decode(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc["schema_version"] != "1" {
		t.Errorf("schema_version = %v", doc["schema_version"])
	}
	return doc
}

func TestHelp(t *testing.T) {
	out, code := runBinary(t, "--help")
	if code != 0 || !strings.Contains(out, "Exit codes:") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestVersion(t *testing.T) {
	out, code := runBinary(t, "version")
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.HasPrefix(out, "zonelint ") {
		t.Errorf("version output: %s", out)
	}
	if want := os.Getenv("ZONELINT_EXPECT_VERSION"); want != "" && !strings.Contains(out, want) {
		t.Errorf("version = %q, want %q", out, want)
	}
}

func TestAuditJSON(t *testing.T) {
	// Audit against a public resolver. This exercises the full pipeline.
	// Flags must precede the domain: the CLI parses flags until the first
	// non-flag argument, so `--json` has to come before the zone name.
	out, code := runBinary(t, "--json", "example.test.")
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	doc := decode(t, out)
	if doc["zone"] != "example.test." {
		t.Errorf("zone = %v", doc["zone"])
	}
	if _, ok := doc["summary"]; !ok {
		t.Errorf("missing summary")
	}
}
