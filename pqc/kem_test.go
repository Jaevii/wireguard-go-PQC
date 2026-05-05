package pqc

import (
	"bytes"
	"testing"

	"golang.zx2c4.com/wireguard/pqc/kems"
)

// helper runs a basic round-trip for a KEM implementation.
func kemRoundTripHelper(t *testing.T, name string, kem kems.KEM) {
	t.Helper()

	pk, sk, err := kem.GenerateKeypair()
	if err != nil {
		t.Fatalf("%s: GenerateKeypair error: %v", name, err)
	}
	if got, want := len(pk), kem.PublicKeySize(); got != want {
		t.Fatalf("%s: public key size mismatch: got %d want %d", name, got, want)
	}
	if got, want := len(sk), kem.PrivateKeySize(); got != want {
		t.Fatalf("%s: private key size mismatch: got %d want %d", name, got, want)
	}

	ct, ss1, err := kem.Encapsulate(pk)
	if err != nil {
		t.Fatalf("%s: Encapsulate error: %v", name, err)
	}
	if got, want := len(ct), kem.CiphertextSize(); got != want {
		t.Fatalf("%s: ciphertext size mismatch: got %d want %d", name, got, want)
	}
	if got, want := len(ss1), kem.SharedSecretSize(); got != want {
		t.Fatalf("%s: shared secret size mismatch: got %d want %d", name, got, want)
	}

	ss2, err := kem.Decapsulate(sk, ct)
	if err != nil {
		t.Fatalf("%s: Decapsulate error: %v", name, err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatalf("%s: shared secrets differ", name)
	}
}

func TestMLKEM512(t *testing.T) {
	kem := kems.NewMLKEM512()
	kemRoundTripHelper(t, "ML-KEM-512", kem)
}

func TestMLKEM768(t *testing.T) {
	kem := kems.NewMLKEM768()
	kemRoundTripHelper(t, "ML-KEM-768", kem)
}

func TestMLKEM1024(t *testing.T) {
	kem := kems.NewMLKEM1024()
	kemRoundTripHelper(t, "ML-KEM-1024", kem)
}

func TestHQC128(t *testing.T) {
	kem := kems.NewHQC128()
	kemRoundTripHelper(t, "HQC-128", kem)
}

func TestHybridMLKEM512(t *testing.T) {
	cfg, err := NewConfig(ModeHybridMLKEM512)
	if err != nil {
		t.Fatal(err)
	}
	kemRoundTripHelper(t, ModeHybridMLKEM512, cfg.KEM())
}

func TestHybridMLKEM768(t *testing.T) {
	cfg, err := NewConfig(ModeHybridMLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	kemRoundTripHelper(t, ModeHybridMLKEM768, cfg.KEM())
}

func TestHybridMLKEM1024(t *testing.T) {
	cfg, err := NewConfig(ModeHybridMLKEM1024)
	if err != nil {
		t.Fatal(err)
	}
	kemRoundTripHelper(t, ModeHybridMLKEM1024, cfg.KEM())
}

func TestHybridHQC128(t *testing.T) {
	cfg, err := NewConfig(ModeHybridHQC128)
	if err != nil {
		t.Fatal(err)
	}
	kemRoundTripHelper(t, ModeHybridHQC128, cfg.KEM())
}
