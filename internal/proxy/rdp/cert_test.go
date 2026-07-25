package rdp

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The portal keeps its certificate in a subdirectory that nothing creates
// beforehand, so a fresh install used to fail on the first start.
func TestCertIsCreatedInAMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web")

	cert, err := LoadOrCreateCert(dir, "gw.example.com", "", "")
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate returned")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := leaf.VerifyHostname("gw.example.com"); err != nil {
		t.Errorf("hostname not covered: %v", err)
	}
}

func TestCertIsReusedOnRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web")

	first, err := LoadOrCreateCert(dir, "gw.example.com", "", "")
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	second, err := LoadOrCreateCert(dir, "gw.example.com", "", "")
	if err != nil {
		t.Fatalf("restart: %v", err)
	}

	// A new certificate on every restart would break pinning and passkeys.
	if string(first.Certificate[0]) != string(second.Certificate[0]) {
		t.Error("certificate was regenerated instead of reused")
	}
}

func TestPrivateKeyIsNotReadableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}

	dir := filepath.Join(t.TempDir(), "web")
	if _, err := LoadOrCreateCert(dir, "gw.example.com", "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "rdp-key.pem"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("private key is %v, want no group or world access", perm)
	}
}
