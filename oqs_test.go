// oqs_test.go
package main

import (
	"bytes"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func TestMLKEMSmoke(t *testing.T) {
	kem := oqs.KeyEncapsulation{}
	defer kem.Clean()

	if err := kem.Init("ML-KEM-768", nil); err != nil {
		t.Fatalf("failed to init ML-KEM-768: %v", err)
	}

	pubKey, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	ciphertext, sharedSecretServer, err := kem.EncapSecret(pubKey)
	if err != nil {
		t.Fatalf("encap failed: %v", err)
	}

	sharedSecretClient, err := kem.DecapSecret(ciphertext)
	if err != nil {
		t.Fatalf("decap failed: %v", err)
	}

	if !bytes.Equal(sharedSecretServer, sharedSecretClient) {
		t.Fatal("shared secrets do not match")
	}
}
