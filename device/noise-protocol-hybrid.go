/*
 * Hybrid KEM Noise variant implementation.
 */

package device

import (
	"golang.org/x/crypto/blake2s"
	"golang.zx2c4.com/wireguard/pqc/kems"
)

// hybridMixInitiatorKEM is called inside CreateMessageInitiation after the
// classical transcript is complete (after mixHash(msg.Timestamp[:])).
// It generates an ephemeral KEM keypair, appends the public key to msg.Ephemeral
// after the X25519 public key, and mixes it into the transcript hash.
// The private key is stored in handshake.kemEphemeralPriv for later use in
// hybridMixInitiatorResponse, where the responder's KEM ciphertext is decapsulated.
//
// Wire format: msg.Ephemeral = X25519_pk(32) ++ KEM_pk(N)
func hybridMixInitiatorKEM(handshake *Handshake, msg *MessageInitiation, kem kems.KEM) error {
	// Generate ephemeral KEM keypair
	kemPub, kemPriv, err := kem.GenerateKeypair()
	if err != nil {
		return err
	}

	// Append ephemeral KEM public key to msg.Ephemeral after X25519
	msg.Ephemeral = append(msg.Ephemeral, kemPub...)

	// Mix public key into transcript
	handshake.mixHash(kemPub)

	// Store private key — needed to decapsulate the responder's ciphertext
	handshake.kemEphemeralPriv = kemPriv

	return nil
}

// hybridMixResponderKEM is called inside ConsumeMessageInitiation after
// the classical transcript is verified and handshake state is being written.
// It reads the initiator's ephemeral KEM public key from msg.Ephemeral[32:],
// mixes it into the transcript hash, and stores a defensive copy in
// handshake.remoteKEM for use in hybridMixResponseKEM.
//
// msg.Ephemeral[32:] contains the initiator's KEM public key.
func hybridMixResponderKEM(handshake *Handshake, msg *MessageInitiation, kem kems.KEM) error {
	if len(msg.Ephemeral) != NoisePublicKeySize+kem.PublicKeySize() {
		return errInvalidPublicKey
	}

	kemPub := msg.Ephemeral[NoisePublicKeySize:]
	handshake.remoteKEM = make([]byte, len(kemPub))
	copy(handshake.remoteKEM, kemPub)

	// Mix into transcript — must match initiator ordering
	handshake.mixHash(kemPub)

	return nil
}

// hybridMixResponseKEM is called inside CreateMessageResponse after the
// classical response transcript is complete (after mixHash(msg.Empty[:])).
// It encapsulates to the initiator's ephemeral KEM public key stored in
// handshake.kemSharedSecret, appends the ciphertext to msg.Ephemeral after the
// X25519 public key, and mixes the ciphertext into the transcript hash.
// The KEM shared secret is stored in handshake.kemSharedSecret to be consumed
// by BeginSymmetricSession as a mandatory input to session key derivation.
//
// Wire format: msg.Ephemeral = X25519_pk(32) ++ KEM_ct(N)
func hybridMixResponseKEM(handshake *Handshake, msg *MessageResponse, kem kems.KEM) error {
	ciphertext, sharedSecret, err := kem.Encapsulate(kems.PublicKey(handshake.remoteKEM))
	if err != nil {
		return err
	}
	// Store shared secret for BeginSymmetricSession — do NOT mix into chainKey here
	handshake.kemSharedSecret = make([]byte, len(sharedSecret))
	copy(handshake.kemSharedSecret, sharedSecret)
	setZero(sharedSecret)

	msg.Ephemeral = append(msg.Ephemeral, ciphertext...)

	// Still mix ciphertext into the transcript hash for authentication
	handshake.mixHash(ciphertext)
	return nil
}

// hybridMixInitiatorResponse is called inside ConsumeMessageResponse after
// the classical transcript is verified.
// It decapsulates the responder's KEM ciphertext using the initiator's ephemeral
// KEM private key stored in handshake.kemEphemeralPriv, mixes the ciphertext into the
// transcript hash, then overwrites handshake.kemSharedSecret with the resulting shared
// secret for consumption by BeginSymmetricSession.
// Note: operates on the hash and chainKey pointers passed in from the ok() closure
// in ConsumeMessageResponse, not on handshake.hash/chainKey directly, since those
// fields are not yet committed at this point in the handshake flow.
//
// msg.Ephemeral[32:] contains the responder's KEM ciphertext.
func hybridMixInitiatorResponse(handshake *Handshake, msg *MessageResponse, hash *[blake2s.Size]byte, kem kems.KEM) error {
	if len(msg.Ephemeral) != NoisePublicKeySize+kem.CiphertextSize() {
		return errInvalidPublicKey
	}
	ciphertext := msg.Ephemeral[NoisePublicKeySize:]

	sharedSecret, err := kem.Decapsulate(kems.PrivateKey(handshake.kemEphemeralPriv), ciphertext)
	if err != nil {
		return err
	}

	// Mix ciphertext into transcript hash for authentication binding
	mixHash(hash, hash, ciphertext)

	// Zero and release the ephemeral private key — it has served its purpose.
	// Store the resulting shared secret for BeginSymmetricSession.
	setZero(handshake.kemEphemeralPriv)
	handshake.kemEphemeralPriv = nil

	handshake.kemSharedSecret = make([]byte, len(sharedSecret))
	copy(handshake.kemSharedSecret, sharedSecret)
	setZero(sharedSecret)

	return nil
}
