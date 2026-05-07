package kems

import (
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// KEM represents a Key Encapsulation Mechanism.
type KEM interface {
	// GenerateKeypair generates a fresh ephemeral keypair.
	GenerateKeypair() (PublicKey, PrivateKey, error)

	// Encapsulate takes a peer's public key, produces:
	//   - ciphertext to send to the peer
	//   - shared secret (never transmitted)
	Encapsulate(peerPK PublicKey) (ciphertext []byte, sharedSecret []byte, err error)

	// Decapsulate takes our private key and the peer's ciphertext, recovers
	// the shared secret.
	Decapsulate(sk PrivateKey, ciphertext []byte) (sharedSecret []byte, err error)

	// Sizes — needed so the handshake buffer knows what to allocate.
	PublicKeySize() int
	PrivateKeySize() int
	CiphertextSize() int
	SharedSecretSize() int

	// Name returns a canonical string for logging/metrics.
	Name() string
}

type PublicKey []byte
type PrivateKey []byte

// liboqsKEM is the shared implementation for all liboqs-backed KEMs.
// mlkem and hqc embed this struct — they get GenerateKeypair, Encapsulate,
// and Decapsulate for free. They only need to implement the size methods
// and Name(), which differ per variant.
//
// liboqsKEM holds no mutable state — variant is set once at construction
// and never changes. All oqs.KeyEncapsulation handles are created locally
// within each method and cleaned before the method returns.
type liboqsKEM struct {
	variant string // liboqs algorithm name e.g. "ML-KEM-768", "HQC-128"
}

func (k *liboqsKEM) GenerateKeypair() (PublicKey, PrivateKey, error) {
	handle, err := k.newHandle(nil)
	if err != nil {
		return nil, nil, err
	}
	defer handle.Clean()

	pk, err := handle.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("%s GenerateKeypair: %w", k.variant, err)
	}
	return PublicKey(cloneBytes(pk)), PrivateKey(cloneBytes(handle.ExportSecretKey())), nil
}

func (k *liboqsKEM) Encapsulate(peerPK PublicKey) ([]byte, []byte, error) {
	handle, err := k.newHandle(nil)
	if err != nil {
		return nil, nil, err
	}
	defer handle.Clean()

	ct, ss, err := handle.EncapSecret([]byte(peerPK))
	if err != nil {
		return nil, nil, fmt.Errorf("%s Encapsulate: %w", k.variant, err)
	}
	return cloneBytes(ct), cloneBytes(ss), nil
}

func (k *liboqsKEM) Decapsulate(sk PrivateKey, ct []byte) ([]byte, error) {
	// Copy sk into a local buffer so handle.Clean() cannot zero the caller's key material
	skCopy := make([]byte, len(sk))
	copy(skCopy, sk)
	handle, err := k.newHandle(skCopy)
	if err != nil {
		return nil, err
	}
	defer handle.Clean()
	ss, err := handle.DecapSecret(ct)
	if err != nil {
		return nil, fmt.Errorf("%s Decapsulate: %w", k.variant, err)
	}
	return cloneBytes(ss), nil
}

func (k *liboqsKEM) newHandle(sk []byte) (oqs.KeyEncapsulation, error) {
	var handle oqs.KeyEncapsulation
	if err := handle.Init(k.variant, sk); err != nil {
		return oqs.KeyEncapsulation{}, fmt.Errorf("%s init: %w", k.variant, err)
	}
	return handle, nil
}

// cloneBytes copies liboqs return values into Go-managed memory.
// liboqs return values point into C-managed memory that becomes invalid
// after handle.Clean() is called. Since defer runs before the return
// values are handed to the caller, without cloning the caller receives
// a pointer to freed C memory.
func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
