package pqc

// Package pqc provides KEM mode selection for WireGuard-go.
// It maps a mode name to a KEM instance. All algorithm-specific
// knowledge (sizes, liboqs names, security levels) lives in the
// kems/ subpackage.

import (
	"fmt"
	"os"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/poly1305"
	"golang.zx2c4.com/wireguard/pqc/kems"
	"golang.zx2c4.com/wireguard/tai64n"
)

// kemType encodes which handshake variant a Config uses.
// Set once in NewConfig, never changes.
type kemType uint8

const (
	kemTypeClassic kemType = iota
	kemTypePure            // KEM only, no X25519
	kemTypeHybrid          // X25519 + KEM
)

// Mode names accepted by FromString and WIREGUARD_KEM.
const (
	ModeClassic         = "classic"
	ModeMLKEM512        = "mlkem512"
	ModeMLKEM768        = "mlkem768"
	ModeMLKEM1024       = "mlkem1024"
	ModeHQC128          = "hqc128"
	ModeHQC192          = "hqc192"
	ModeHQC256          = "hqc256"
	ModeHybridMLKEM512  = "hybrid-mlkem512"
	ModeHybridMLKEM768  = "hybrid-mlkem768"
	ModeHybridMLKEM1024 = "hybrid-mlkem1024"
	ModeHybridHQC128    = "hybrid-hqc128"
	ModeHybridHQC192    = "hybrid-hqc192"
	ModeHybridHQC256    = "hybrid-hqc256"
)

type registryEntry struct {
	factory func() kems.KEM
	kind    kemType
}

var registry = map[string]registryEntry{
	ModeClassic: {nil, kemTypeClassic},

	ModeMLKEM512:  {kems.NewMLKEM512, kemTypePure},
	ModeMLKEM768:  {kems.NewMLKEM768, kemTypePure},
	ModeMLKEM1024: {kems.NewMLKEM1024, kemTypePure},

	ModeHQC128: {kems.NewHQC128, kemTypePure},
	ModeHQC192: {kems.NewHQC192, kemTypePure},
	ModeHQC256: {kems.NewHQC256, kemTypePure},

	ModeHybridMLKEM512:  {kems.NewMLKEM512, kemTypeHybrid},
	ModeHybridMLKEM768:  {kems.NewMLKEM768, kemTypeHybrid},
	ModeHybridMLKEM1024: {kems.NewMLKEM1024, kemTypeHybrid},

	ModeHybridHQC128: {kems.NewHQC128, kemTypeHybrid},
	ModeHybridHQC192: {kems.NewHQC192, kemTypeHybrid},
	ModeHybridHQC256: {kems.NewHQC256, kemTypeHybrid},
}

// Config is an immutable KEM selection bound to a Device.
// The zero value is invalid — use NewConfig or ConfigFromEnv.
// Pass by value; there is nothing to lock because nothing can change.
type Config struct {
	name string   // the mode string, kept for logging
	kem  kems.KEM // nil for Classic
	kind kemType
}

// NewConfig validates the mode name and returns a Config.
// Returns an error for unrecognised names.
func NewConfig(modeName string) (Config, error) {
	entry, ok := registry[modeName]
	if !ok {
		return Config{}, fmt.Errorf("pqc: unknown mode %q; valid: %s",
			modeName, validNames())
	}
	c := Config{name: modeName,
		kind: entry.kind}
	if entry.factory != nil {
		c.kem = entry.factory()
	}
	return c, nil
}

// ConfigFromEnv reads WIREGUARD_KEM. Unset → Classic.
func ConfigFromEnv() (Config, error) {
	s := os.Getenv("WIREGUARD_KEM")
	if s == "" {
		return NewConfig(ModeClassic)
	}
	cfg, err := NewConfig(s)
	if err != nil {
		return Config{}, fmt.Errorf("pqc: WIREGUARD_KEM=%q: %w", s, err)
	}
	return cfg, nil
}

// KEM returns the KEM instance. Nil for Classic mode.
func (c Config) KEM() kems.KEM { return c.kem }

// IsClassic reports whether the unmodified WireGuard handshake is used.
func (c Config) IsClassic() bool { return c.kind == kemTypeClassic }

// IsPureKEM reports whether a KEM-only handshake is used (no X25519).
func (c Config) IsPureKEM() bool { return c.kind == kemTypePure }

// IsHybrid reports whether an X25519 + KEM handshake is used.
func (c Config) IsHybrid() bool { return c.kind == kemTypeHybrid }

// String returns the mode name for logging.
func (c Config) String() string { return c.name }

// MessageInitiationSize returns the wire size of a MessageInitiation for this config.
//
// Wire layout:
//
//	Classical:  [Type:4][Sender:4][X25519_eph:32][Static+tag:48][Timestamp+tag:28][MAC1:16][MAC2:16] = 148
//	Hybrid:     [Type:4][Sender:4][X25519_eph:32][KEM_pk:N][Static+tag:48][Timestamp+tag:28][MAC1:16][MAC2:16]
//	Pure KEM:   [Type:4][Sender:4][KEM_pk:N][KEM_ct:M][KEM_Static+tag:N+16][Timestamp+tag:28][MAC1:16][MAC2:16]
func (c Config) MessageInitiationSize() int {
	const (
		x25519Size      = 32
		typeAndSender   = 8
		staticAndTag    = x25519Size + poly1305.TagSize
		timestampAndTag = tai64n.TimestampSize + poly1305.TagSize
		mac1            = blake2s.Size128
		mac2            = blake2s.Size128
		trailer         = staticAndTag + timestampAndTag + mac1 + mac2
	)
	switch {
	case c.IsClassic():
		return typeAndSender + x25519Size + trailer
	case c.IsPureKEM():
		return typeAndSender +
			c.kem.PublicKeySize() +
			c.kem.CiphertextSize() +
			c.MessageStaticSize() +
			timestampAndTag + mac1 + mac2
	default: // Hybrid
		return typeAndSender + x25519Size + c.kem.PublicKeySize() + trailer
	}
}

// MessageResponseSize returns the wire size of a MessageResponse for this config.
//
// Wire layout:
//
//	Classical:  [Type:4][Sender:4][Receiver:4][X25519_eph:32][Empty+tag:16][MAC1:16][MAC2:16] = 92
//	Hybrid:     [Type:4][Sender:4][Receiver:4][X25519_eph:32][KEM_ct:N][Empty+tag:16][MAC1:16][MAC2:16]
//	Pure KEM:   [Type:4][Sender:4][Receiver:4][KEM_ct:N][Empty+tag:16][MAC1:16][MAC2:16]
func (c Config) MessageResponseSize() int {
	const (
		x25519Size            = 32
		typeAndSenderReceiver = 12
		emptyAndTag           = poly1305.TagSize // 16
		mac1                  = blake2s.Size128  // 16
		mac2                  = blake2s.Size128  // 16
		fixedTrailer          = emptyAndTag + mac1 + mac2
	)

	switch {
	case c.IsClassic():
		return typeAndSenderReceiver + x25519Size + fixedTrailer
	case c.IsPureKEM():
		return typeAndSenderReceiver + c.kem.CiphertextSize() + fixedTrailer
	default: // Hybrid
		return typeAndSenderReceiver + x25519Size + c.kem.CiphertextSize() + fixedTrailer
	}
}

func (c Config) MessageStaticSize() int {
	if c.IsPureKEM() {
		return c.kem.PublicKeySize() + poly1305.TagSize
	}
	return 32 + poly1305.TagSize // 48
}

// MessageKEMCTSize returns the size of the KEMCT field in a MessageInitiation.
// Zero for classical and hybrid modes.
func (c Config) MessageKEMCTSize() int {
	if c.IsPureKEM() {
		return c.kem.CiphertextSize()
	}
	return 0
}

// InitiationEphemeralSize returns the byte length of the ephemeral field
// in a MessageInitiation.
//
//	Classical: 32  (X25519 public key)
//	Hybrid:    32 + KEM public key size
//	Pure KEM:  KEM public key size
func (c Config) InitiationEphemeralSize() int {
	const x25519Size = 32
	switch {
	case c.IsClassic():
		return x25519Size
	case c.IsPureKEM():
		return c.kem.PublicKeySize()
	default: // Hybrid
		return x25519Size + c.kem.PublicKeySize()
	}
}

// ResponseEphemeralSize returns the byte length of the ephemeral field
// in a MessageResponse.
//
//	Classical: 32  (X25519 public key)
//	Hybrid:    32 + KEM ciphertext size
//	Pure KEM:  KEM ciphertext size
func (c Config) ResponseEphemeralSize() int {
	const x25519Size = 32
	switch {
	case c.IsClassic():
		return x25519Size
	case c.IsPureKEM():
		return c.kem.CiphertextSize()
	default: // Hybrid
		return x25519Size + c.kem.CiphertextSize()
	}
}

func validNames() string {
	names := make([]string, 0, len(registry))
	for k := range registry {
		names = append(names, k)
	}
	return fmt.Sprintf("%v", names)
}
