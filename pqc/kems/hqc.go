package kems

const (
	// HQC-128 (L1)
	HQC128PublicKeySize    = 2249
	HQC128PrivateKeySize   = 2305
	HQC128CiphertextSize   = 4433
	HQC128SharedSecretSize = 64

	// HQC-192 (L2)
	HQC192PublicKeySize    = 4522
	HQC192PrivateKeySize   = 4586
	HQC192CiphertextSize   = 8978
	HQC192SharedSecretSize = 64

	// HQC-256 (L3)
	HQC256PublicKeySize    = 7245
	HQC256PrivateKeySize   = 7317
	HQC256CiphertextSize   = 14421
	HQC256SharedSecretSize = 64
)

// Supported variants: "HQC-128", "HQC-192", "HQC-256"
type hqc128 struct{ liboqsKEM }
type hqc192 struct{ liboqsKEM }
type hqc256 struct{ liboqsKEM }

func NewHQC128() KEM { return &hqc128{liboqsKEM{"HQC-128"}} }
func NewHQC192() KEM { return &hqc192{liboqsKEM{"HQC-192"}} }
func NewHQC256() KEM { return &hqc256{liboqsKEM{"HQC-256"}} }

func (h *hqc128) PublicKeySize() int    { return HQC128PublicKeySize }
func (h *hqc128) PrivateKeySize() int   { return HQC128PrivateKeySize }
func (h *hqc128) CiphertextSize() int   { return HQC128CiphertextSize }
func (h *hqc128) SharedSecretSize() int { return HQC128SharedSecretSize }
func (h *hqc128) Name() string          { return "HQC-128" }

func (h *hqc192) PublicKeySize() int    { return HQC192PublicKeySize }
func (h *hqc192) PrivateKeySize() int   { return HQC192PrivateKeySize }
func (h *hqc192) CiphertextSize() int   { return HQC192CiphertextSize }
func (h *hqc192) SharedSecretSize() int { return HQC192SharedSecretSize }
func (h *hqc192) Name() string          { return "HQC-192" }

func (h *hqc256) PublicKeySize() int    { return HQC256PublicKeySize }
func (h *hqc256) PrivateKeySize() int   { return HQC256PrivateKeySize }
func (h *hqc256) CiphertextSize() int   { return HQC256CiphertextSize }
func (h *hqc256) SharedSecretSize() int { return HQC256SharedSecretSize }
func (h *hqc256) Name() string          { return "HQC-256" }
