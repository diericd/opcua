package uasc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateTestCertDER(t *testing.T) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return der, &key.PublicKey
}

func TestParseCertificate_SingleCert(t *testing.T) {
	der, wantKey := generateTestCertDER(t)

	cert, err := parseCertificate(der)
	if err != nil {
		t.Fatalf("parseCertificate() error = %v", err)
	}
	got := cert.PublicKey.(*rsa.PublicKey)
	if got.N.Cmp(wantKey.N) != 0 || got.E != wantKey.E {
		t.Errorf("parseCertificate() returned wrong certificate")
	}
}

func TestParseCertificate_CertChain(t *testing.T) {
	// Two concatenated DER certificates — parseCertificate should return the first one.
	der1, wantKey := generateTestCertDER(t)
	der2, _ := generateTestCertDER(t)
	chain := append(der1, der2...)

	cert, err := parseCertificate(chain)
	if err != nil {
		t.Fatalf("parseCertificate() error = %v", err)
	}
	got := cert.PublicKey.(*rsa.PublicKey)
	if got.N.Cmp(wantKey.N) != 0 || got.E != wantKey.E {
		t.Errorf("parseCertificate() returned wrong certificate from chain")
	}
}

func TestParseCertificate_InvalidData(t *testing.T) {
	_, err := parseCertificate([]byte("not a certificate"))
	if err == nil {
		t.Error("parseCertificate() expected error for invalid data, got nil")
	}
}

func TestParseCertificate_Empty(t *testing.T) {
	_, err := parseCertificate([]byte{})
	if err == nil {
		t.Error("parseCertificate() expected error for empty data, got nil")
	}
}
