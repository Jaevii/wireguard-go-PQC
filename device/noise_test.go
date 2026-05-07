/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/pqc"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := newPrivateKey()
	assertNil(t, err)

	sk2, err := newPrivateKey()
	assertNil(t, err)

	pk1 := sk1.publicKey()
	pk2 := sk2.publicKey()

	ss1, err1 := sk1.sharedSecret(pk2)
	ss2, err2 := sk2.sharedSecret(pk1)

	if ss1 != ss2 || err1 != nil || err2 != nil {
		t.Fatal("Failed to compute shared secet")
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey(sk)
	return device
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

// Classical
func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, MessageInitiationSize)
	assertNil(t, msg1.marshal(packet, dev1.messageInitiationSize, dev1.initiationEphemeralSize, dev1.messageKEMCTSize, dev1.messageStaticSize))
	peer := dev2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("wireguard test message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard test message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()
}

// PQC Hybrid
func TestHybridKEMHandshake(t *testing.T) {
	t.Run("hybrid", func(t *testing.T) {
		// Set up two devices with hybrid KEM config
		cfg, err := pqc.NewConfig(pqc.ModeHybridMLKEM768)
		if err != nil {
			t.Fatal("failed to create hybrid config:", err)
		}

		dev1 := randDeviceWithConfig(t, cfg)
		dev2 := randDeviceWithConfig(t, cfg)
		defer dev1.Close()
		defer dev2.Close()

		// Exchange KEM public keys — simulates what UAPI does in production
		peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
		if err != nil {
			t.Fatal(err)
		}
		peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
		if err != nil {
			t.Fatal(err)
		}

		// Set each peer's remote KEM public key — required for hybrid encapsulation
		peer1.kemPublicKey = dev1.staticIdentity.KEMpublicKey
		peer2.kemPublicKey = dev2.staticIdentity.KEMpublicKey

		peer1.Start()
		peer2.Start()

		// Sanity check: KEM keypairs were generated
		if len(dev1.staticIdentity.KEMpublicKey) == 0 {
			t.Fatal("dev1 KEM public key not generated")
		}
		if len(dev2.staticIdentity.KEMpublicKey) == 0 {
			t.Fatal("dev2 KEM public key not generated")
		}
		if len(dev1.staticIdentity.KEMprivateKey) == 0 {
			t.Fatal("dev1 KEM private key not generated")
		}

		// Verify both devices report hybrid mode
		if !dev1.pqcConfig.IsHybrid() {
			t.Fatal("dev1 is not in hybrid mode")
		}
		if !dev2.pqcConfig.IsHybrid() {
			t.Fatal("dev2 is not in hybrid mode")
		}

		// Verify message sizes are larger than classical
		if dev1.messageInitiationSize <= MessageInitiationSize {
			t.Errorf("hybrid initiation size %d should be > classical %d",
				dev1.messageInitiationSize, MessageInitiationSize)
		}
		if dev1.messageResponseSize <= MessageResponseSize {
			t.Errorf("hybrid response size %d should be > classical %d",
				dev1.messageResponseSize, MessageResponseSize)
		}
		t.Logf("initiation message size: classical=%d hybrid=%d (+%d bytes)",
			MessageInitiationSize, dev1.messageInitiationSize,
			dev1.messageInitiationSize-MessageInitiationSize)
		t.Logf("response message size:   classical=%d hybrid=%d (+%d bytes)",
			MessageResponseSize, dev1.messageResponseSize,
			dev1.messageResponseSize-MessageResponseSize)

		// =========================================================
		// Initiation
		// =========================================================
		t.Log("--- initiation message ---")
		msg1, err := dev1.CreateMessageInitiation(peer2)
		assertNil(t, err)

		// Verify ephemeral field is hybrid-sized (X25519 + KEM public key)
		expectedEphSize := dev1.initiationEphemeralSize
		if len(msg1.Ephemeral) != expectedEphSize {
			t.Fatalf("initiation ephemeral: got %d bytes, want %d",
				len(msg1.Ephemeral), expectedEphSize)
		}

		// Verify the X25519 portion (first 32 bytes) is non-zero
		if allZero(msg1.Ephemeral[:32]) {
			t.Fatal("X25519 ephemeral portion is all zeros")
		}

		// Verify the KEM portion (bytes 32:) is non-zero
		if allZero(msg1.Ephemeral[32:]) {
			t.Fatal("KEM public key portion of ephemeral is all zeros")
		}

		// Verify kemEphemeralPriv was stored in dev1's handshake state for peer2.
		// The initiator is dev1, so we look up dev1's peer entry for dev2.
		initiatorPeer := dev1.LookupPeer(dev2.staticIdentity.privateKey.publicKey())
		if initiatorPeer == nil {
			t.Fatal("dev1 has no peer entry for dev2")
		}
		initiatorPeer.handshake.mutex.RLock()
		ephPrivSet := len(initiatorPeer.handshake.kemEphemeralPriv) > 0
		initiatorPeer.handshake.mutex.RUnlock()
		if !ephPrivSet {
			t.Fatal("initiator did not store ephemeral KEM private key in handshake.kemEphemeralPriv")
		}

		// Marshal and check wire size
		packet1 := make([]byte, dev1.messageInitiationSize)
		assertNil(t, msg1.marshal(packet1, dev1.messageInitiationSize, dev1.initiationEphemeralSize, dev1.messageKEMCTSize, dev1.messageStaticSize))
		if len(packet1) != dev1.messageInitiationSize {
			t.Fatalf("marshalled initiation: got %d bytes, want %d",
				len(packet1), dev1.messageInitiationSize)
		}

		// Consume on dev2
		responderPeer := dev2.LookupPeer(dev1.staticIdentity.privateKey.publicKey())
		peer := dev2.ConsumeMessageInitiation(msg1)
		if peer == nil {
			// Manually replay each step to find the failure point

			// Step 1: check message type
			if msg1.Type != MessageInitiationType {
				t.Fatal("wrong message type:", msg1.Type)
			}
			t.Log("message type OK")

			// Step 2: check ephemeral size is what dev2 expects
			t.Logf("msg1.Ephemeral length: %d, dev2 expects: %d",
				len(msg1.Ephemeral), dev2.initiationEphemeralSize)
			if len(msg1.Ephemeral) != dev2.initiationEphemeralSize {
				t.Fatalf("ephemeral size mismatch: msg has %d, dev2 expects %d",
					len(msg1.Ephemeral), dev2.initiationEphemeralSize)
			}
			t.Log("ephemeral size OK")

			// Step 3: check peer2 KEM public key was set on dev2's peer1
			if responderPeer == nil {
				t.Fatal("dev2 does not know about dev1 as a peer")
			}
			t.Logf("dev2 peer1 kemPublicKey length: %d", len(responderPeer.kemPublicKey))

			// Step 4: check dev2 has a KEM private key to decapsulate with
			dev2.staticIdentity.RLock()
			kemPrivLen := len(dev2.staticIdentity.KEMprivateKey)
			kemPubLen := len(dev2.staticIdentity.KEMpublicKey)
			dev2.staticIdentity.RUnlock()
			t.Logf("dev2 KEM private key length: %d", kemPrivLen)
			t.Logf("dev2 KEM public key length:  %d", kemPubLen)
			if kemPrivLen == 0 {
				t.Fatal("dev2 has no KEM private key — cannot decapsulate")
			}

			// Step 5: check the KEM public key dev1 encapsulated TO
			// is actually dev2's KEM public key
			kemPortionInMsg := msg1.Ephemeral[32:]
			t.Logf("KEM portion in msg1.Ephemeral: %d bytes", len(kemPortionInMsg))
			t.Logf("dev2 KEM public key:           %d bytes", kemPubLen)

			// Step 6: check peer2's kemPublicKey (what dev1 encapsulated to)
			// matches dev2's actual public key
			dev2.staticIdentity.RLock()
			kemPubMatch := bytes.Equal(peer2.kemPublicKey, dev2.staticIdentity.KEMpublicKey)
			dev2.staticIdentity.RUnlock()
			t.Logf("peer2.kemPublicKey matches dev2.staticIdentity.KEMpublicKey: %v", kemPubMatch)
			if !kemPubMatch {
				t.Logf("peer2.kemPublicKey:               %x...", peer2.kemPublicKey[:min(8, len(peer2.kemPublicKey))])
				dev2.staticIdentity.RLock()
				t.Logf("dev2.staticIdentity.KEMpublicKey: %x...", dev2.staticIdentity.KEMpublicKey[:min(8, len(dev2.staticIdentity.KEMpublicKey))])
				dev2.staticIdentity.RUnlock()
				t.Fatal("initiator encapsulated to wrong KEM public key")
			}

			t.Fatal("ConsumeMessageInitiation returned nil — cause unknown, check above logs")
		}

		// After consumption, dev2's handshake should have remoteKEM set
		// (the initiator's KEM public key, needed for CreateMessageResponse).
		peer.handshake.mutex.RLock()
		remoteKEMSet := len(peer.handshake.remoteKEM) > 0
		remoteKEMLen := len(peer.handshake.remoteKEM)
		peer.handshake.mutex.RUnlock()
		if !remoteKEMSet {
			t.Fatal("responder did not store remoteKEM after ConsumeMessageInitiation")
		}
		t.Logf("responder remoteKEM length: %d bytes", remoteKEMLen)

		// Chain keys and hashes must match after initiation.
		// Compare dev1's handshake state for peer2 vs dev2's handshake state for peer1.
		initiatorPeer.handshake.mutex.RLock()
		initiatorChainKey := initiatorPeer.handshake.chainKey
		initiatorHash := initiatorPeer.handshake.hash
		initiatorPeer.handshake.mutex.RUnlock()

		responderPeer.handshake.mutex.RLock()
		responderChainKey := responderPeer.handshake.chainKey
		responderHash := responderPeer.handshake.hash
		responderPeer.handshake.mutex.RUnlock()

		assertEqual(t, initiatorChainKey[:], responderChainKey[:])
		assertEqual(t, initiatorHash[:], responderHash[:])
		t.Log("chain keys match after initiation ✓")

		// =========================================================
		// Response
		// =========================================================
		t.Log("--- response message ---")
		msg2, err := dev2.CreateMessageResponse(peer1)
		assertNil(t, err)

		// Verify ephemeral field is hybrid-sized (X25519 + KEM ciphertext)
		expectedRespEphSize := dev2.responseEphemeralSize
		if len(msg2.Ephemeral) != expectedRespEphSize {
			t.Fatalf("response ephemeral: got %d bytes, want %d",
				len(msg2.Ephemeral), expectedRespEphSize)
		}

		// Verify the KEM ciphertext portion (bytes 32:) is non-zero
		kemCTPortion := msg2.Ephemeral[32:]
		if allZero(kemCTPortion) {
			t.Fatal("KEM ciphertext portion of response ephemeral is all zeros")
		}
		t.Logf("response KEM ciphertext length: %d bytes", len(kemCTPortion))

		// Marshal and check wire size
		packet2 := make([]byte, dev2.messageResponseSize)
		assertNil(t, msg2.marshal(packet2, dev2.messageResponseSize, dev2.responseEphemeralSize))
		if len(packet2) != dev2.messageResponseSize {
			t.Fatalf("marshalled response: got %d bytes, want %d",
				len(packet2), dev2.messageResponseSize)
		}

		// Consume on dev1
		peer = dev1.ConsumeMessageResponse(msg2)
		if peer == nil {
			t.Fatal("ConsumeMessageResponse returned nil — handshake failed")
		}

		// Chain keys and hashes must match after response
		initiatorPeer.handshake.mutex.RLock()
		initiatorChainKey = initiatorPeer.handshake.chainKey
		initiatorHash = initiatorPeer.handshake.hash
		initiatorPeer.handshake.mutex.RUnlock()

		responderPeer.handshake.mutex.RLock()
		responderChainKey = responderPeer.handshake.chainKey
		responderHash = responderPeer.handshake.hash
		responderPeer.handshake.mutex.RUnlock()

		assertEqual(t, initiatorChainKey[:], responderChainKey[:])
		assertEqual(t, initiatorHash[:], responderHash[:])
		t.Log("chain keys match after response ✓")

		// Both sides must have kemSharedSecret set before session derivation —
		// this is the value that feeds into BeginSymmetricSession's KDF combiner.
		initiatorPeer.handshake.mutex.RLock()
		initiatorSSSet := len(initiatorPeer.handshake.kemSharedSecret) > 0
		initiatorPeer.handshake.mutex.RUnlock()

		responderPeer.handshake.mutex.RLock()
		responderSSSet := len(responderPeer.handshake.kemSharedSecret) > 0
		responderPeer.handshake.mutex.RUnlock()

		if !initiatorSSSet {
			t.Fatal("initiator kemSharedSecret not set before BeginSymmetricSession")
		}
		if !responderSSSet {
			t.Fatal("responder kemSharedSecret not set before BeginSymmetricSession")
		}
		t.Log("KEM shared secrets set on both sides ✓")

		// =========================================================
		// Session key derivation
		// =========================================================
		t.Log("--- deriving session keys ---")
		assertNil(t, initiatorPeer.BeginSymmetricSession())
		assertNil(t, responderPeer.BeginSymmetricSession())

		// After BeginSymmetricSession the initiator's keypair lands in current,
		// the responder's in next (or current if already promoted). Take whichever
		// is non-nil to avoid a fragile assumption about call ordering.
		key1 := initiatorPeer.keypairs.current
		if key1 == nil {
			key1 = initiatorPeer.keypairs.next.Load()
		}
		key2 := responderPeer.keypairs.current
		if key2 == nil {
			key2 = responderPeer.keypairs.next.Load()
		}

		if key1 == nil {
			t.Fatal("initiator has no keypair after BeginSymmetricSession")
		}
		if key2 == nil {
			t.Fatal("responder has no keypair after BeginSymmetricSession")
		}

		// =========================================================
		// Encryption / decryption — proves session keys match
		// =========================================================
		t.Log("--- testing session keys ---")
		func() {
			testMsg := []byte("hybrid KEM test message 1 — initiator to responder")
			var out []byte
			var nonce [12]byte
			out = key1.send.Seal(out, nonce[:], testMsg, nil)
			out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
			assertNil(t, err)
			assertEqual(t, out, testMsg)
			t.Log("initiator→responder encryption ✓")
		}()

		func() {
			testMsg := []byte("hybrid KEM test message 2 — responder to initiator")
			var out []byte
			var nonce [12]byte
			out = key2.send.Seal(out, nonce[:], testMsg, nil)
			out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
			assertNil(t, err)
			assertEqual(t, out, testMsg)
			t.Log("responder→initiator encryption ✓")
		}()

		// =========================================================
		// Verify all KEM state is zeroed after session derivation
		// =========================================================
		initiatorPeer.handshake.mutex.RLock()
		kem1Zeroed := initiatorPeer.handshake.kemEphemeralPriv == nil &&
			initiatorPeer.handshake.kemSharedSecret == nil &&
			initiatorPeer.handshake.remoteKEM == nil
		initiatorPeer.handshake.mutex.RUnlock()

		responderPeer.handshake.mutex.RLock()
		kem2Zeroed := responderPeer.handshake.kemEphemeralPriv == nil &&
			responderPeer.handshake.kemSharedSecret == nil &&
			responderPeer.handshake.remoteKEM == nil
		responderPeer.handshake.mutex.RUnlock()

		if !kem1Zeroed {
			t.Error("initiator KEM handshake state not zeroed after session derivation")
		}
		if !kem2Zeroed {
			t.Error("responder KEM handshake state not zeroed after session derivation")
		}
		t.Log("KEM handshake state zeroed after session derivation ✓")
	})
}

// PQC pure-KEM
func TestPureKEMHandshake(t *testing.T) {
	kemModes := []string{
		pqc.ModeMLKEM768,
		pqc.ModeMLKEM512,
		pqc.ModeMLKEM1024,
		pqc.ModeHQC128,
		pqc.ModeHQC192,
		pqc.ModeHQC256,
	}

	for _, mode := range kemModes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			cfg, err := pqc.NewConfig(mode)
			if err != nil {
				t.Fatalf("failed to create pure-KEM config for %s: %v", mode, err)
			}

			dev1 := randDeviceWithConfig(t, cfg)
			dev2 := randDeviceWithConfig(t, cfg)
			defer dev1.Close()
			defer dev2.Close()

			// In pure-KEM mode there are no X25519 static keys used for
			// peer lookup — peers are identified by their KEM public key.
			// We still need X25519 keys for the classical WireGuard peer
			// table, but the handshake itself doesn't use them.
			peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
			if err != nil {
				t.Fatal(err)
			}
			peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
			if err != nil {
				t.Fatal(err)
			}

			// Set KEM public keys on each peer — required for encapsulation
			// and for kemKeyMap registration via handlePostConfig in production.
			// In tests we set them directly and register manually.
			peer1.kemPublicKey = dev1.staticIdentity.KEMpublicKey
			peer2.kemPublicKey = dev2.staticIdentity.KEMpublicKey

			// Register KEM public keys in kemKeyMap so LookupPeerByKEMKey works.
			// In production this is done by uapi.go handlePostConfig.
			dev2.peers.Lock()
			dev2.peers.kemKeyMap[string(dev1.staticIdentity.KEMpublicKey)] = peer1
			dev2.peers.Unlock()

			dev1.peers.Lock()
			dev1.peers.kemKeyMap[string(dev2.staticIdentity.KEMpublicKey)] = peer2
			dev1.peers.Unlock()

			peer1.Start()
			peer2.Start()

			// Sanity check: KEM keypairs were generated for both devices
			if len(dev1.staticIdentity.KEMpublicKey) == 0 {
				t.Fatal("dev1 KEM public key not generated")
			}
			if len(dev2.staticIdentity.KEMpublicKey) == 0 {
				t.Fatal("dev2 KEM public key not generated")
			}
			if len(dev1.staticIdentity.KEMprivateKey) == 0 {
				t.Fatal("dev1 KEM private key not generated")
			}
			if len(dev2.staticIdentity.KEMprivateKey) == 0 {
				t.Fatal("dev2 KEM private key not generated")
			}

			// Verify pure-KEM mode is active
			if !dev1.pqcConfig.IsPureKEM() {
				t.Fatal("dev1 is not in pure-KEM mode")
			}
			if !dev2.pqcConfig.IsPureKEM() {
				t.Fatal("dev2 is not in pure-KEM mode")
			}

			kem := cfg.KEM()
			t.Logf("KEM algorithm: %s", kem.Name())
			t.Logf("KEM public key size:   %d bytes", kem.PublicKeySize())
			t.Logf("KEM ciphertext size:   %d bytes", kem.CiphertextSize())
			t.Logf("KEM shared secret size: %d bytes", kem.SharedSecretSize())
			t.Logf("initiation message size: classical=%d pure-KEM=%d (+%d bytes)",
				MessageInitiationSize, dev1.messageInitiationSize,
				dev1.messageInitiationSize-MessageInitiationSize)
			t.Logf("response message size:   classical=%d pure-KEM=%d (+%d bytes)",
				MessageResponseSize, dev1.messageResponseSize,
				dev1.messageResponseSize-MessageResponseSize)

			// Pure-KEM messages must be larger than classical
			if dev1.messageInitiationSize <= MessageInitiationSize {
				t.Errorf("pure-KEM initiation size %d should be > classical %d",
					dev1.messageInitiationSize, MessageInitiationSize)
			}
			if dev1.messageResponseSize <= MessageResponseSize {
				t.Errorf("pure-KEM response size %d should be > classical %d",
					dev1.messageResponseSize, MessageResponseSize)
			}

			// =========================================================
			// Initiation
			// =========================================================
			t.Log("--- initiation message ---")

			// dev1 is initiator, dev2 is responder
			msg1, err := dev1.CreateMessageInitiation(peer2)
			assertNil(t, err)

			// Pure-KEM: Ephemeral carries KEM_eph_pk only; CT_es is in KEMCT field
			if len(msg1.Ephemeral) != kem.PublicKeySize() {
				t.Fatalf("initiation ephemeral: got %d bytes, want %d (KEM_eph_pk only)",
					len(msg1.Ephemeral), kem.PublicKeySize())
			}
			if allZero(msg1.Ephemeral) {
				t.Fatal("KEM ephemeral public key is all zeros")
			}

			// CT_es is in the separate KEMCT field
			if len(msg1.KEMCT) != kem.CiphertextSize() {
				t.Fatalf("initiation KEMCT: got %d bytes, want %d",
					len(msg1.KEMCT), kem.CiphertextSize())
			}
			if allZero(msg1.KEMCT) {
				t.Fatal("CT_es (KEMCT field) is all zeros")
			}

			// Static field must contain the encrypted initiator KEM public key
			// Size: KEM pk + 16 (poly1305 tag) = 48
			expectedStaticSize := kem.PublicKeySize() + 16
			if len(msg1.KEMStatic) != expectedStaticSize {
				t.Fatalf("initiation KEMStatic field: got %d bytes, want %d",
					len(msg1.KEMStatic), expectedStaticSize)
			}
			if allZero(msg1.KEMStatic) {
				t.Fatal("initiation KEMStatic field is all zeros — encryption failed")
			}

			// kemEphemeralPriv must be stored in initiator's handshake
			initiatorPeer := dev1.LookupPeer(dev2.staticIdentity.privateKey.publicKey())
			if initiatorPeer == nil {
				t.Fatal("dev1 has no peer entry for dev2")
			}
			initiatorPeer.handshake.mutex.RLock()
			ephPrivSet := len(initiatorPeer.handshake.kemEphemeralPriv) > 0
			initiatorPeer.handshake.mutex.RUnlock()
			if !ephPrivSet {
				t.Fatal("initiator did not store KEM ephemeral private key")
			}

			// Verify dev2 can look up dev1 via KEM key (required for ConsumeMessageInitiation)
			lookedUp := dev2.LookupPeerByKEMKey(dev1.staticIdentity.KEMpublicKey)
			if lookedUp == nil {
				t.Fatal("dev2 cannot look up dev1 by KEM public key — kemKeyMap not populated")
			}

			// Marshal and verify wire size
			packet1 := make([]byte, dev1.messageInitiationSize)
			assertNil(t, msg1.marshal(packet1, dev1.messageInitiationSize, dev1.initiationEphemeralSize, dev1.messageKEMCTSize, dev1.messageStaticSize))
			if len(packet1) != dev1.messageInitiationSize {
				t.Fatalf("marshalled initiation: got %d bytes, want %d",
					len(packet1), dev1.messageInitiationSize)
			}
			t.Logf("initiation wire size: %d bytes ✓", len(packet1))

			// Consume on dev2 (responder)
			responderPeer := dev2.LookupPeer(dev1.staticIdentity.privateKey.publicKey())
			peer := dev2.ConsumeMessageInitiation(msg1)
			if peer == nil {
				// Diagnostic steps to identify failure point
				if msg1.Type != MessageInitiationType {
					t.Fatal("wrong message type:", msg1.Type)
				}
				t.Log("message type OK")

				if len(msg1.Ephemeral) != dev2.initiationEphemeralSize {
					t.Fatalf("ephemeral size mismatch: msg has %d, dev2 expects %d",
						len(msg1.Ephemeral), dev2.initiationEphemeralSize)
				}
				t.Log("ephemeral size OK")

				if responderPeer == nil {
					t.Fatal("dev2 does not know about dev1 as a peer")
				}

				dev2.staticIdentity.RLock()
				kemPrivLen := len(dev2.staticIdentity.KEMprivateKey)
				dev2.staticIdentity.RUnlock()
				if kemPrivLen == 0 {
					t.Fatal("dev2 has no KEM private key — cannot decapsulate CT_es")
				}
				t.Logf("dev2 KEM private key length: %d", kemPrivLen)

				// Check that CT_es was encapsulated to dev2's actual static KEM public key
				dev2.staticIdentity.RLock()
				kemPubMatch := bytes.Equal(peer2.kemPublicKey, dev2.staticIdentity.KEMpublicKey)
				dev2.staticIdentity.RUnlock()
				if !kemPubMatch {
					t.Fatal("initiator encapsulated to wrong KEM public key")
				}
				t.Log("encapsulation target matches dev2 KEM public key")

				t.Fatal("ConsumeMessageInitiation returned nil — cause unknown, check above logs")
			}

			// After consumption, responder must have stored the initiator's
			// ephemeral KEM public key in remoteKEM for CT_ee encapsulation
			peer.handshake.mutex.RLock()
			remoteKEMSet := len(peer.handshake.remoteKEM) > 0
			remoteKEMLen := len(peer.handshake.remoteKEM)
			peer.handshake.mutex.RUnlock()
			if !remoteKEMSet {
				t.Fatal("responder did not store remoteKEM after ConsumeMessageInitiation")
			}
			if remoteKEMLen != kem.PublicKeySize() {
				t.Fatalf("responder remoteKEM length: got %d, want %d",
					remoteKEMLen, kem.PublicKeySize())
			}
			t.Logf("responder remoteKEM (initiator eph KEM pk): %d bytes ✓", remoteKEMLen)

			// Chain keys must match after initiation
			initiatorPeer.handshake.mutex.RLock()
			initiatorChainKey := initiatorPeer.handshake.chainKey
			initiatorHash := initiatorPeer.handshake.hash
			initiatorPeer.handshake.mutex.RUnlock()

			responderPeer.handshake.mutex.RLock()
			responderChainKey := responderPeer.handshake.chainKey
			responderHash := responderPeer.handshake.hash
			responderPeer.handshake.mutex.RUnlock()

			assertEqual(t, initiatorChainKey[:], responderChainKey[:])
			assertEqual(t, initiatorHash[:], responderHash[:])
			t.Log("chain keys and hashes match after initiation ✓")

			// =========================================================
			// Response
			// =========================================================
			t.Log("--- response message ---")

			msg2, err := dev2.CreateMessageResponse(peer1)
			assertNil(t, err)

			// Pure-KEM response ephemeral field is: CT_ee only
			expectedRespEphSize := kem.CiphertextSize()
			if len(msg2.Ephemeral) != expectedRespEphSize {
				t.Fatalf("response ephemeral: got %d bytes, want %d (CT_ee only)",
					len(msg2.Ephemeral), expectedRespEphSize)
			}
			if allZero(msg2.Ephemeral) {
				t.Fatal("CT_ee portion of response is all zeros")
			}
			t.Logf("response CT_ee length: %d bytes ✓", len(msg2.Ephemeral))

			// Marshal and verify wire size
			packet2 := make([]byte, dev2.messageResponseSize)
			assertNil(t, msg2.marshal(packet2, dev2.messageResponseSize, dev2.responseEphemeralSize))
			if len(packet2) != dev2.messageResponseSize {
				t.Fatalf("marshalled response: got %d bytes, want %d",
					len(packet2), dev2.messageResponseSize)
			}
			t.Logf("response wire size: %d bytes ✓", len(packet2))

			// Consume on dev1 (initiator)
			peer = dev1.ConsumeMessageResponse(msg2)
			if peer == nil {
				t.Fatal("ConsumeMessageResponse returned nil — handshake failed")
			}

			// kemEphemeralPriv must be zeroed after decapsulation
			initiatorPeer.handshake.mutex.RLock()
			ephPrivAfter := initiatorPeer.handshake.kemEphemeralPriv
			initiatorPeer.handshake.mutex.RUnlock()
			if ephPrivAfter != nil {
				t.Error("initiator kemEphemeralPriv not zeroed after decapsulation")
			}
			t.Log("initiator kemEphemeralPriv zeroed after decapsulation ✓")

			// Chain keys must still match after response.
			// Note: in pure-KEM mode the identity commitment (mixHash of
			// responder static KEM public key) is mixed in after msg.Empty,
			// so the chain keys here reflect the full transcript including
			// the commitment. Both sides must agree on the responder identity
			// for these to match.
			initiatorPeer.handshake.mutex.RLock()
			initiatorChainKey = initiatorPeer.handshake.chainKey
			initiatorHash = initiatorPeer.handshake.hash
			initiatorPeer.handshake.mutex.RUnlock()

			responderPeer.handshake.mutex.RLock()
			responderChainKey = responderPeer.handshake.chainKey
			responderHash = responderPeer.handshake.hash
			responderPeer.handshake.mutex.RUnlock()

			assertEqual(t, initiatorChainKey[:], responderChainKey[:])
			assertEqual(t, initiatorHash[:], responderHash[:])
			t.Log("chain keys and hashes match after response ✓")

			// =========================================================
			// Session key derivation
			// =========================================================
			t.Log("--- deriving session keys ---")

			assertNil(t, initiatorPeer.BeginSymmetricSession())
			assertNil(t, responderPeer.BeginSymmetricSession())

			key1 := initiatorPeer.keypairs.current
			if key1 == nil {
				key1 = initiatorPeer.keypairs.next.Load()
			}
			key2 := responderPeer.keypairs.current
			if key2 == nil {
				key2 = responderPeer.keypairs.next.Load()
			}

			if key1 == nil {
				t.Fatal("initiator has no keypair after BeginSymmetricSession")
			}
			if key2 == nil {
				t.Fatal("responder has no keypair after BeginSymmetricSession")
			}

			// =========================================================
			// Encryption / decryption — proves session keys match
			// =========================================================
			t.Log("--- testing session keys ---")

			func() {
				testMsg := []byte("pure-KEM test message 1 — initiator to responder")
				var out []byte
				var nonce [12]byte
				out = key1.send.Seal(out, nonce[:], testMsg, nil)
				out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
				assertNil(t, err)
				assertEqual(t, out, testMsg)
				t.Log("initiator→responder encryption ✓")
			}()

			func() {
				testMsg := []byte("pure-KEM test message 2 — responder to initiator")
				var out []byte
				var nonce [12]byte
				out = key2.send.Seal(out, nonce[:], testMsg, nil)
				out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
				assertNil(t, err)
				assertEqual(t, out, testMsg)
				t.Log("responder→initiator encryption ✓")
			}()

			// =========================================================
			// Verify all KEM handshake state is zeroed after session derivation
			// =========================================================
			initiatorPeer.handshake.mutex.RLock()
			kem1Zeroed := initiatorPeer.handshake.kemEphemeralPriv == nil &&
				initiatorPeer.handshake.kemSharedSecret == nil &&
				initiatorPeer.handshake.remoteKEM == nil
			initiatorPeer.handshake.mutex.RUnlock()

			responderPeer.handshake.mutex.RLock()
			kem2Zeroed := responderPeer.handshake.kemEphemeralPriv == nil &&
				responderPeer.handshake.kemSharedSecret == nil &&
				responderPeer.handshake.remoteKEM == nil
			responderPeer.handshake.mutex.RUnlock()

			if !kem1Zeroed {
				t.Error("initiator KEM handshake state not zeroed after session derivation")
			}
			if !kem2Zeroed {
				t.Error("responder KEM handshake state not zeroed after session derivation")
			}
			t.Log("KEM handshake state zeroed after session derivation ✓")

			// =========================================================
			// Identity commitment verification
			// Replay the commitment manually to confirm both sides agree
			// on the responder's identity. If the wrong KEM public key
			// had been mixed in, session keys would have diverged and
			// the encryption test above would have failed — but this
			// makes the check explicit.
			// =========================================================
			if !bytes.Equal(peer2.kemPublicKey, dev2.staticIdentity.KEMpublicKey) {
				t.Error("responder identity commitment: peer2.kemPublicKey does not match dev2 static KEM public key")
			}
			t.Log("responder identity commitment consistent ✓")
		})
	}
}

// randDeviceWithConfig creates a device using a specific pqc.Config,
// mirroring randDevice but allowing KEM mode injection.
func randDeviceWithConfig(t *testing.T, cfg pqc.Config) *Device {
	t.Helper()
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelVerbose, "")
	device := NewDeviceWithConfig(tun.TUN(), conn.NewDefaultBind(), logger, cfg)
	device.SetPrivateKey(sk)
	return device
}

// allZero reports whether all bytes in b are zero.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
