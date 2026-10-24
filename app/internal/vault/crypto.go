package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

// KDFParams are the Argon2id costs stored with each vault so later versions can raise them.
type KDFParams struct {
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
}

// DefaultKDF is the cost used for new vaults. Re-measure on target machines before release.
var DefaultKDF = KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// Upper bounds protect against a tampered header exhausting memory or CPU during unlock.
const (
	maxKDFTime   = 10
	maxKDFMemory = 1 << 20 // 1 GiB in KiB
	keyLen       = 32
	saltLen      = 16
)

var errBadKDF = errors.New("vault: unsupported key derivation parameters")

func (p KDFParams) validate() error {
	if p.Time < 1 || p.Time > maxKDFTime || p.MemoryKiB < 8*1024 || p.MemoryKiB > maxKDFMemory || p.Threads < 1 {
		return errBadKDF
	}
	return nil
}

func deriveKey(password, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
}

// seal encrypts with AES-256-GCM; the random nonce is prepended to the ciphertext.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, aad), nil
}

func open(key, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, ciphertext, aad)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("vault: system random source failed: " + err.Error())
	}
	return b
}

// wipe overwrites a buffer. Go may still hold copies elsewhere; this only shortens exposure.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
