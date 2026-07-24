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
		// Regenerate well before expiry rather than on the day it breaks.
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			if time.Until(leaf.NotAfter) > 30*24*time.Hour {
				return cert, nil
			}
		}
	}

	cert, crtPEM, keyPEM, err := selfSigned(hostname)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err := os.WriteFile(crtPath, crtPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write rdp certificate: %w", err)
	}
	// The private key must never be group- or world-readable.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write rdp key: %w", err)
	}

	slog.Info("generated a self-signed certificate for the rdp listener",
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

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"Revpd"}},
		DNSNames:     []string{hostname},
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
