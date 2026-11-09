package main

// Certificate validation, staging, hashing and fingerprint extraction.
//
// The staged file naming matches upstream cmd/derper/cert.go manual certmode
// exactly, so derper reads the certs we stage.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Identical to upstream cmd/derper/cert.go unsafeHostnameCharacters, so staged
// file names match what derper's manual certmode reads.
var unsafeHostnameCharacters = regexp.MustCompile(`[^a-zA-Z0-9-\.]`)

// derperCertPaths returns the cert paths derper's manual certmode actually reads.
func derperCertPaths(certDir, hostname string) (crtPath, keyPath string) {
	keyname := unsafeHostnameCharacters.ReplaceAllString(hostname, "")
	return filepath.Join(certDir, keyname+".crt"), filepath.Join(certDir, keyname+".key")
}

func hashPEM(certPEM, keyPEM []byte) string {
	h := sha256.New()
	h.Write(certPEM)
	h.Write(keyPEM)
	return hex.EncodeToString(h.Sum(nil))
}

// certFileHash reads the real bytes of the cert and key files (following
// symlinks) and computes their combined SHA-256.
func certFileHash(certPath, keyPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	return hashPEM(certPEM, keyPEM), nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stageAndValidateCert validates the user-provided certificate and stages it
// atomically into derper's manual cert directory:
//  1. read real bytes (following symlinks) and compute the combined hash;
//  2. tls.X509KeyPair to verify the pair is complete and matching;
//  3. leaf certificate must not be expired;
//  4. custom_selfsigned additionally requires exactly one certificate (a CA
//     chain would trigger "unexpected multiple certs presented" in Tailscale
//     clients);
//  5. external_letsencrypt additionally requires the cert to match hostname.
func stageAndValidateCert(d *DerperConfig) (string, error) {
	certPEM, err := os.ReadFile(d.CertFile)
	if err != nil {
		return "", fmt.Errorf("failed to read cert_file: %w", err)
	}
	keyPEM, err := os.ReadFile(d.KeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read key_file: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", fmt.Errorf("cert/key mismatch or corrupt files: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return "", fmt.Errorf("certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if d.CertMode == "custom_selfsigned" && len(pair.Certificate) != 1 {
		return "", fmt.Errorf("custom_selfsigned allows exactly one self-signed certificate (got %d; a CA chain triggers \"unexpected multiple certs presented\" in Tailscale clients)", len(pair.Certificate))
	}
	if d.CertMode == "external_letsencrypt" {
		if err := leaf.VerifyHostname(d.Hostname); err != nil {
			return "", fmt.Errorf("certificate does not match hostname %q: %w", d.Hostname, err)
		}
	}
	if err := os.MkdirAll(d.CertDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create cert_dir: %w", err)
	}
	crtPath, keyPath := derperCertPaths(d.CertDir, d.Hostname)
	if err := writeFileAtomic(crtPath, certPEM, 0600); err != nil {
		return "", fmt.Errorf("failed to stage certificate: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
		return "", fmt.Errorf("failed to stage private key: %w", err)
	}
	log.Printf("[CERT] certificate validated and staged: %s", crtPath)
	return hashPEM(certPEM, keyPEM), nil
}

// extractCertRawSHA256 reads the first CERTIFICATE PEM block and returns a
// "sha256-raw:<hex>" fingerprint, ready to paste into an ACL derpMap CertName.
func extractCertRawSHA256(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no PEM CERTIFICATE block found in %s", certPath)
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256-raw:" + hex.EncodeToString(sum[:]), nil
}
