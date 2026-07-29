package rdp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreateCert returns the certificate the RDP listener presents.
//
// A self-signed certificate is fine here and is what a stock Windows host uses
// too: mstsc shows the same "identity cannot be verified" prompt either way.
// What actually protects the credentials is that they never leave the TLS
// tunnel, and that the gateway is the only thing holding the private key.
//
// Give it a real certificate via certFile/keyFile if you want the prompt gone.
func LoadOrCreateCert(dir, hostname, certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load rdp certificate: %w", err)
		}
		return cert, nil
	}

	crtPath := filepath.Join(dir, "rdp-cert.pem")
	keyPath := filepath.Join(dir, "rdp-key.pem")

	if cert, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			// Regenerate well before expiry rather than on the day it breaks,
			// and also when the machine's own address has moved on since this
			// was made — a new DHCP lease, or a cert from before this
			// covered IPs at all. Otherwise a perfectly good certificate keeps
			// getting rejected by name for as long as it has left to run.
			if time.Until(leaf.NotAfter) > 30*24*time.Hour && coversLocalAddresses(leaf) {
				return cert, nil
			}
		}
	}

	cert, crtPEM, keyPEM, err := selfSigned(hostname)
	if err != nil {
		return tls.Certificate{}, err
	}

	// The portal keeps its pair in a subdirectory of the data directory, which
	// the installer has no reason to know about.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate directory: %w", err)
	}

	if err := os.WriteFile(crtPath, crtPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write rdp certificate: %w", err)
	}
	// The private key must never be group- or world-readable.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write rdp key: %w", err)
	}

	slog.Info("generated a self-signed certificate",
		"hostname", hostname, "path", crtPath, "valid_days", 825)
	return cert, nil
}

func selfSigned(hostname string) (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	if hostname == "" {
		hostname = "revpd"
	}

	dnsNames, ips := sanFor(hostname)

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"Revpd"}},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		// 825 days is the longest most clients still accept.
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("marshal key: %w", err)
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, crtPEM, keyPEM, nil
}

// coversLocalAddresses reports whether every address a client could type to
// reach this machine right now is already on the certificate. Missing one
// that used to be covered is not a reason to regenerate — a laptop that
// unplugged from Ethernet is not renewing its certificate over it — only a
// currently-held address that is not covered is.
func coversLocalAddresses(leaf *x509.Certificate) bool {
	for _, ip := range localIPs() {
		covered := false
		for _, want := range leaf.IPAddresses {
			if want.Equal(ip) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// sanFor works out what the certificate has to cover.
//
// A hostname is rarely the only thing typed at this gateway. Somebody without
// DNS set up connects by LAN address instead — mstsc especially, since it
// checks the address against the certificate the way RFC 6125 says to: an IP
// typed by the user is only ever compared against IPAddresses, never against a
// DNSName that happens to look like one. A certificate covering only the
// configured hostname made every IP connection show a second, more alarming
// "the name does not match" warning on top of the expected self-signed one.
//
// So this covers every address the machine could plausibly be reached at:
// loopback always, and whatever a network interface is holding right now.
func sanFor(hostname string) (dnsNames []string, ips []net.IP) {
	dnsNames = []string{"localhost"}
	ips = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	} else if hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}

	for _, ip := range localIPs() {
		ips = append(ips, ip)
	}

	return dedupStrings(dnsNames), dedupIPs(ips)
}

// localIPs lists the addresses this machine currently holds on a real
// interface — not loopback, not link-local, and not the placeholder address a
// down interface reports. Best-effort: a machine mid-DHCP-renewal is not a
// reason to fail startup, so an error here is silently an empty list rather
// than a returned error.
func localIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	var out []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsUnspecified() {
			continue
		}
		out = append(out, ipNet.IP)
	}
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupIPs(in []net.IP) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	for _, ip := range in {
		k := ip.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, ip)
		}
	}
	return out
}
