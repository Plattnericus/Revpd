package rdp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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

/*
mstsc checks the address the user typed against the certificate the way
RFC 6125 says to: an IP is only ever compared against IPAddresses, never
against a DNSName that happens to look like one. A certificate that only
covered the configured hostname made every connection by IP — the normal
case on a home network without a DNS entry — show a second, more alarming
"the name does not match" warning on top of the self-signed one every RDP
client shows anyway.
*/
func TestCertCoversLoopbackByAddress(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web")

	cert, err := LoadOrCreateCert(dir, "gw.example.com", "", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	for _, addr := range []string{"127.0.0.1", "::1"} {
		if err := leaf.VerifyHostname(addr); err != nil {
			t.Errorf("VerifyHostname(%q) = %v, want covered", addr, err)
		}
	}
}

// A gateway on a LAN is reached by its own address at least as often as by
// its configured hostname, since setting up DNS for a home network is the
// exception rather than the rule.
func TestCertCoversTheMachinesOwnAddresses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web")

	cert, err := LoadOrCreateCert(dir, "gw.example.com", "", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	own := localIPs()
	if len(own) == 0 {
		t.Skip("this machine reports no non-loopback address to check against")
	}
	for _, ip := range own {
		if err := leaf.VerifyHostname(ip.String()); err != nil {
			t.Errorf("VerifyHostname(%q) = %v, want covered — this machine's own address", ip, err)
		}
	}
}

// Setting the hostname itself to a bare IP — not unusual on a gateway with no
// domain name at all — must not silently produce a certificate that only
// matches that IP string as a DNS label, which no client would ever ask for.
func TestCertHandlesAnIPAsTheConfiguredHostname(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web")

	cert, err := LoadOrCreateCert(dir, "203.0.113.9", "", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := leaf.VerifyHostname("203.0.113.9"); err != nil {
		t.Errorf("the configured address is not covered: %v", err)
	}
	for _, dns := range leaf.DNSNames {
		if dns == "203.0.113.9" {
			t.Error("an IP address ended up in DNSNames — RFC 6125 clients will never match it there")
		}
	}
}

// A certificate made before this machine had the address it does now — a new
// DHCP lease, or one written by a version that did not cover IPs at all — has
// to be replaced rather than kept until it happens to expire.
func TestCertIsRegeneratedWhenItStopsCoveringTheMachine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	stale := writeCertCoveringOnly(t, dir, "gw.example.com")

	cert, err := LoadOrCreateCert(dir, "gw.example.com", "", "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(cert.Certificate[0]) == string(stale.Certificate[0]) {
		t.Fatal("the stale certificate, which covers no address this machine holds, was reused as-is")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("the replacement still does not cover loopback: %v", err)
	}
}

// writeCertCoveringOnly stands in for a certificate from before this code
// covered any address at all — hostname only, the shape LoadOrCreateCert used
// to produce.
func writeCertCoveringOnly(t *testing.T, dir, hostname string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(dir, "rdp-cert.pem"), crtPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rdp-key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der}}
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
