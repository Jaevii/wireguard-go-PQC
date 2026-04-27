// oqs_test.go
package main

import (
	"bytes"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func runKEMSmoke(t *testing.T, alg string) {
	t.Helper()

	kem := oqs.KeyEncapsulation{}
	defer kem.Clean()

	if err := kem.Init(alg, nil); err != nil {
		t.Fatalf("failed to init %s: %v", alg, err)
	}

	pubKey, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("%s keygen failed: %v", alg, err)
	}

	ciphertext, sharedSecretServer, err := kem.EncapSecret(pubKey)
	if err != nil {
		t.Fatalf("%s encap failed: %v", alg, err)
	}

	sharedSecretClient, err := kem.DecapSecret(ciphertext)
	if err != nil {
		t.Fatalf("%s decap failed: %v", alg, err)
	}

	if !bytes.Equal(sharedSecretServer, sharedSecretClient) {
		t.Fatalf("%s shared secrets do not match", alg)
	}
}

func TestMLKEMSmoke(t *testing.T) {
	runKEMSmoke(t, "ML-KEM-768")
}

func TestHQCSmoke(t *testing.T) {
	runKEMSmoke(t, "HQC-128")
}
