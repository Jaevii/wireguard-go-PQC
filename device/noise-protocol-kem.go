/*
 * Pure KEM-only Noise variant implementation.
 * This file implements KEM-first handshake operations for pqc.Config pure modes.
 */

package device

import (
	"errors"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/pqc/kems"
	"golang.zx2c4.com/wireguard/tai64n"
)

const PQKEMNoiseConstruction = "Noise_KEM_IKpsk2_ChaChaPoly_BLAKE2s"

// kemInitialTranscript derives the starting chain key and hash for the
// pure-KEM handshake variant. Mixing in the KEM algorithm name ensures
// that ML-KEM-768 and HQC-128 sessions cannot be confused even though
// they share the same construction string.
func kemInitialTranscript(kem kems.KEM) ([blake2s.Size]byte, [blake2s.Size]byte) {
	chainKey := blake2s.Sum256([]byte(PQKEMNoiseConstruction))
	var hash [blake2s.Size]byte
	mixHash(&hash, &chainKey, []byte(WGIdentifier))
	mixHash(&hash, &hash, []byte(kem.Name()))
	return chainKey, hash
}

// KEMCreateMessageInitiation creates a pure-KEM handshake initiation message.
//
// Transcript contributions in order:
//  1. Responder's static KEM public key  (identity commitment)
//  2. Initiator's ephemeral KEM public key + mixKey
//  3. CT_es ciphertext + ssES into chain key  (es operation)
//  4. Encrypted initiator static KEM public key
//  5. Encrypted timestamp
func (device *Device) KEMCreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	kem := device.pqcConfig.KEM()

	// Initialise transcript with KEM-specific construction
	chainKey, hash := kemInitialTranscript(kem)
	handshake.chainKey = chainKey
	handshake.hash = hash

	// Commit to the responder's identity before generating key material.
	// Mirrors mixHash(remoteStatic) in the classical handshake.
	handshake.mixHash(peer.kemPublicKey)

	// --- Operation 1: generate initiator ephemeral KEM keypair ---
	// kemEphPub is sent on the wire. kemEphPriv is stored for decapsulation
	// of CT_ee in the response. Stored only after all fallible operations
	// to avoid leaving key material in the handshake on error paths.
	kemEphPub, kemEphPriv, err := kem.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	handshake.mixHash(kemEphPub)
	handshake.mixKey(kemEphPub)

	// --- Operation 2: encapsulate to responder's static KEM public key (es) ---
	// Proves the initiator knows the responder's long-term public key.
	// CT_es is sent on the wire appended after the ephemeral public key.
	// ssES enters the chain key and is never transmitted.
	ctES, ssES, err := kem.Encapsulate(kems.PublicKey(peer.kemPublicKey))
	if err != nil {
		return nil, err
	}
	defer setZero(ssES)
	handshake.mixHash(ctES)
	handshake.mixKey(ssES)

	// Encrypt our static KEM public key, authenticated against the current
	// transcript hash. Allows the responder to look up our peer entry.
	var key [chacha20poly1305.KeySize]byte
	KDF2(&handshake.chainKey, &key, handshake.chainKey[:], nil)
	aead, _ := chacha20poly1305.New(key[:])

	var msg MessageInitiation
	msg.Type = MessageInitiationType
	// Ephemeral field carries: KEM_eph_pk ++ CT_es
	msg.Ephemeral = kemEphPub
	msg.KEMCT = ctES
	msg.KEMStatic = aead.Seal(nil, ZeroNonce[:], device.staticIdentity.KEMpublicKey, handshake.hash[:])
	handshake.mixHash(msg.KEMStatic)

	// Encrypt timestamp for replay protection
	KDF2(&handshake.chainKey, &key, handshake.chainKey[:], nil)
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])
	handshake.mixHash(msg.Timestamp[:])

	// Assign sender index — done last so we don't leak an index on error
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	// Store private key only after all fallible operations have succeeded
	handshake.kemEphemeralPriv = kemEphPriv

	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

// KEMConsumeMessageInitiation processes a pure-KEM handshake initiation.
//
// Mirrors the transcript construction of KEMCreateMessageInitiation exactly.
// On success, stores the initiator's ephemeral KEM public key in remoteKEM
// for use by KEMCreateMessageResponse.
func (device *Device) KEMConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	kem := device.pqcConfig.KEM()

	// Validate and split Ephemeral field: KEM_eph_pk ++ CT_es
	if len(msg.Ephemeral) != kem.PublicKeySize() {
		return nil
	}
	if len(msg.KEMCT) != kem.CiphertextSize() {
		return nil
	}
	kemEphPub := msg.Ephemeral
	ctES := msg.KEMCT

	// Reconstruct transcript — must mirror KEMCreateMessageInitiation exactly
	chainKey, hash := kemInitialTranscript(kem)
	mixHash(&hash, &hash, device.staticIdentity.KEMpublicKey)
	mixHash(&hash, &hash, kemEphPub)
	mixKey(&chainKey, &chainKey, kemEphPub)

	// Decapsulate CT_es using our static KEM private key
	ssES, err := kem.Decapsulate(kems.PrivateKey(device.staticIdentity.KEMprivateKey), ctES)
	if err != nil {
		return nil
	}
	defer setZero(ssES)
	mixHash(&hash, &hash, ctES)
	mixKey(&chainKey, &chainKey, ssES)

	// Decrypt initiator's static KEM public key
	var key [chacha20poly1305.KeySize]byte
	KDF2(&chainKey, &key, chainKey[:], nil)
	aead, _ := chacha20poly1305.New(key[:])
	initiatorKEMpub := make([]byte, kem.PublicKeySize())
	_, err = aead.Open(initiatorKEMpub[:0], ZeroNonce[:], msg.KEMStatic, hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.KEMStatic)

	// NOTE: LookupPeerByKEMKey runs unconditionally after decapsulation so that
	// the success and failure paths have similar timing. A fully constant-time
	// implementation would require a dummy handshake path on lookup failure;
	// this is a best-effort mitigation.
	peer := device.LookupPeerByKEMKey(initiatorKEMpub)

	// Derive the timestamp decryption key regardless of whether we found the
	// peer, so that a missing peer does not produce a measurably faster return.
	var timestampKey [chacha20poly1305.KeySize]byte
	KDF2(&chainKey, &timestampKey, chainKey[:], nil)

	if peer == nil {
		device.log.Verbosef("KEMConsumeMessageInitiation: peer not found for initiator KEM key")
		return nil
	}
	if !peer.isRunning.Load() {
		device.log.Verbosef("KEMConsumeMessageInitiation: peer found but not running")
		return nil
	}

	handshake := &peer.handshake

	// Decrypt and verify timestamp under read lock
	var timestamp tai64n.Timestamp
	handshake.mutex.RLock()
	// Re-use the key derived above rather than re-deriving it.
	aead, _ = chacha20poly1305.New(timestampKey[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()

	if replay {
		device.log.Verbosef("%v - KEMConsumeMessageInitiation: replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - KEMConsumeMessageInitiation: flood", peer)
		return nil
	}

	// Commit state under write lock
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// Re-check replay and flood under write lock to close the TOCTOU window
	// between the RLock check above and this commit.
	if !timestamp.After(handshake.lastTimestamp) {
		device.log.Verbosef("%v - KEMConsumeMessageInitiation: replay (write-lock recheck) @ %v", peer, timestamp)
		return nil
	}
	if time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate {
		device.log.Verbosef("%v - KEMConsumeMessageInitiation: flood (write-lock recheck)", peer)
		return nil
	}

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender

	// Store initiator's ephemeral KEM public key for CT_ee encapsulation
	// in KEMCreateMessageResponse
	handshake.remoteKEM = make([]byte, len(kemEphPub))
	copy(handshake.remoteKEM, kemEphPub)

	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	return peer
}

// KEMCreateMessageResponse creates a pure-KEM handshake response message.
//
// Performs one KEM encapsulation (CT_ee) to the initiator's ephemeral public
// key, then mixes a hash commitment to the responder's own static KEM public
// key into the transcript after the AEAD seal. This commitment is what the
// initiator verifies in KEMConsumeMessageResponse to authenticate the responder.
func (device *Device) KEMCreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	kem := device.pqcConfig.KEM()
	var err error

	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	msg := &MessageResponse{
		Type:     MessageResponseType,
		Sender:   handshake.localIndex,
		Receiver: handshake.remoteIndex,
	}

	// --- Operation 3: encapsulate to initiator's ephemeral KEM public key (ee) ---
	// Provides forward secrecy. The initiator's ephemeral private key exists
	// only for this session and is zeroed after decapsulation.
	// CT_ee is the entire Ephemeral field in the response.
	ctEE, ssEE, err := kem.Encapsulate(kems.PublicKey(handshake.remoteKEM))
	if err != nil {
		return nil, err
	}
	defer setZero(ssEE)
	handshake.mixHash(ctEE)
	handshake.mixKey(ssEE)

	msg.Ephemeral = ctEE

	// PSK mix — identical to classical WireGuard
	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	KDF3(&handshake.chainKey, &tau, &key,
		handshake.chainKey[:], handshake.presharedKey[:])
	handshake.mixHash(tau[:])

	// Seal msg.Empty to authenticate the transcript up to this point.
	// Because ssES (from CT_es decapsulation) is in the chain key, only
	// the legitimate responder can produce a valid tag here.
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	handshake.mixHash(msg.Empty[:])

	// Identity commitment: mix our static KEM public key into the transcript
	// after the AEAD. The initiator mirrors this with the expected peer public
	// key. If they disagree on who the responder is, BeginSymmetricSession
	// derives different keys on each side and transport decryption fails.
	// This replaces the CT_ss operation (no extra ciphertext, no extra KEM op).
	device.staticIdentity.RLock()
	handshake.mixHash(device.staticIdentity.KEMpublicKey)
	device.staticIdentity.RUnlock()

	handshake.state = handshakeResponseCreated
	return msg, nil
}

// KEMConsumeMessageResponse processes a pure-KEM handshake response.
//
// Decapsulates CT_ee, verifies the AEAD on msg.Empty, then mirrors the
// responder's identity commitment by mixing the expected peer KEM public
// key into the transcript. The session keys derived by BeginSymmetricSession
// will only match the responder's if both sides agree on the responder identity.
func (device *Device) KEMConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	kem := device.pqcConfig.KEM()

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	if len(msg.Ephemeral) != kem.CiphertextSize() {
		return nil
	}
	ctEE := msg.Ephemeral

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	// Local copies for transcript computation — mirrors classical ConsumeMessageResponse
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {
		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// Seed local transcript from current handshake state
		hash = handshake.hash
		chainKey = handshake.chainKey

		ssEE, err := kem.Decapsulate(
			kems.PrivateKey(handshake.kemEphemeralPriv), ctEE)
		if err != nil {
			return false
		}
		defer setZero(ssEE)

		// Operate on local copies, not handshake fields
		mixHash(&hash, &hash, ctEE)
		mixKey(&chainKey, &chainKey, ssEE)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(&chainKey, &tau, &key, chainKey[:], handshake.presharedKey[:])
		mixHash(&hash, &hash, tau[:])

		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		mixHash(&hash, &hash, lookup.peer.kemPublicKey)

		return true
	}()

	if !ok {
		return nil
	}

	// Commit everything under write lock
	handshake.mutex.Lock()
	handshake.hash = hash
	handshake.chainKey = chainKey
	setZero(handshake.kemEphemeralPriv)
	handshake.kemEphemeralPriv = nil
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed
	handshake.mutex.Unlock()

	return lookup.peer
}
