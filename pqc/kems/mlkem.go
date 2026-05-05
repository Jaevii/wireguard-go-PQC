package kems

const (
	// ML-KEM-512 (L1)
	MLKEM512PublicKeySize    = 800
	MLKEM512PrivateKeySize   = 1632
	MLKEM512CiphertextSize   = 768
	MLKEM512SharedSecretSize = 32

	// ML-KEM-768 (L3)
	MLKEM768PublicKeySize    = 1184
	MLKEM768PrivateKeySize   = 2400
	MLKEM768CiphertextSize   = 1088
	MLKEM768SharedSecretSize = 32

	// ML-KEM-1024 (L5)
	MLKEM1024PublicKeySize    = 1568
	MLKEM1024PrivateKeySize   = 3168
	MLKEM1024CiphertextSize   = 1568
	MLKEM1024SharedSecretSize = 32
)

// Supported variants: "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
// ML-KEM-768 is the NIST recommended level (128-bit PQC security)
type mlkem512 struct{ liboqsKEM }
type mlkem768 struct{ liboqsKEM }
type mlkem1024 struct{ liboqsKEM }

func NewMLKEM512() KEM  { return &mlkem512{liboqsKEM{"ML-KEM-512"}} }
func NewMLKEM768() KEM  { return &mlkem768{liboqsKEM{"ML-KEM-768"}} }
func NewMLKEM1024() KEM { return &mlkem1024{liboqsKEM{"ML-KEM-1024"}} }

func (m *mlkem512) PublicKeySize() int    { return MLKEM512PublicKeySize }
func (m *mlkem512) PrivateKeySize() int   { return MLKEM512PrivateKeySize }
func (m *mlkem512) CiphertextSize() int   { return MLKEM512CiphertextSize }
func (m *mlkem512) SharedSecretSize() int { return MLKEM512SharedSecretSize }
func (m *mlkem512) Name() string          { return "ML-KEM-512" }

func (m *mlkem768) PublicKeySize() int    { return MLKEM768PublicKeySize }
func (m *mlkem768) PrivateKeySize() int   { return MLKEM768PrivateKeySize }
func (m *mlkem768) CiphertextSize() int   { return MLKEM768CiphertextSize }
func (m *mlkem768) SharedSecretSize() int { return MLKEM768SharedSecretSize }
func (m *mlkem768) Name() string          { return "ML-KEM-768" }

func (m *mlkem1024) PublicKeySize() int    { return MLKEM1024PublicKeySize }
func (m *mlkem1024) PrivateKeySize() int   { return MLKEM1024PrivateKeySize }
func (m *mlkem1024) CiphertextSize() int   { return MLKEM1024CiphertextSize }
func (m *mlkem1024) SharedSecretSize() int { return MLKEM1024SharedSecretSize }
func (m *mlkem1024) Name() string          { return "ML-KEM-1024" }
