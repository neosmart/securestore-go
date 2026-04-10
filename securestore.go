package securestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

var ErrSecretNotFound = errors.New("secret not found")

const (
	pbkdf2Rounds = 256000
	masterKeyLen = 32 // 16 bytes for AES-128 + 16 bytes for HMAC-SHA1
)

// pemRegex is used to extract the base64 content from ASCII-armored keys.
var pemRegex = regexp.MustCompile(`(?s)--+BEGIN.*?KEY--+(.*?)--+END.*?KEY--+`)

// vaultEntry represents the internal structure of a secret or sentinel in the JSON vault.
type vaultEntry struct {
	IV      string `json:"iv"`
	HMAC    string `json:"hmac"`
	Payload string `json:"payload"`
}

// vaultData represents the root structure of a SecureStore v3 vault file.
type vaultData struct {
	Version  int                   `json:"version"`
	IV       string                `json:"iv"` // salt
	Sentinel *vaultEntry           `json:"sentinel,omitempty"`
	Secrets  map[string]vaultEntry `json:"secrets"`
}

type sourceType string

const (
	typePassword sourceType = "password"
	typeKey      sourceType = "key"
)

// KeySource is an abstraction over SecureStore password- or key-based decryption
type KeySource struct {
	keyType sourceType
	value   []byte
}

// KeyFromPassword derives decryption keys from the provided password
func KeyFromPassword(password string) *KeySource {
	return &KeySource{
		keyType: typePassword,
		value:   []byte(password),
	}
}

// KeyFromFile loads decryption key from a key file.
// Handles both raw binary and ASCII-armored keys.
func KeyFromFile(path string) (*KeySource, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("SecureStore decryption key not found: %w", err)
	}

	return KeyFromBytes(content)
}

// KeyFromBytes loads decryption key from a raw key.
// Handles both raw binary and ASCII-armored keys.
func KeyFromBytes(key []byte) (*KeySource, error) {
	if len(key) == masterKeyLen {
		// Assume we were provided the raw key
		return &KeySource{keyType: typeKey, value: key}, nil
	}

	// Check for ASCII-armored (PEM-style) format
	keyStr := string(key)
	if strings.Contains(keyStr, "--BEGIN") {
		matches := pemRegex.FindStringSubmatch(keyStr)
		if len(matches) > 1 {
			trimmed := strings.Join(strings.Fields(matches[1]), "")
			decoded, err := base64.StdEncoding.DecodeString(trimmed)
			if err == nil {
				return &KeySource{keyType: typeKey, value: decoded}, nil
			}
		}
	}

	return nil, errors.New("invalid SecureStore decryption key provided")
}

// SecretsManager instances can be used to load and decrypt secrets from SecureStore vaults.
type SecretsManager struct {
	aesKey  []byte
	hmacKey []byte
	secrets map[string]vaultEntry
}

// Load loads a SecureStore vault from disk, decrypting with a key loaded from the provided KeySource.
func LoadFile(path string, keySource *KeySource) (*SecretsManager, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("SecureStore vault not found: %w", err)
	}
	defer file.Close()
	return Load(file, keySource)
}

// Load loads a SecureStore vault, decrypting with a key loaded from the provided KeySource.
func Load(r io.Reader, keySource *KeySource) (*SecretsManager, error) {
	var data vaultData
	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, errors.New("failed to parse SecureStore vault JSON")
	}

	if data.Version != 3 {
		return nil, fmt.Errorf("unsupported SecureStore version %d (library supports v3)", data.Version)
	}

	// Derive or load the master key
	masterKey, err := resolveMasterKey(keySource, data.IV)
	if err != nil {
		return nil, err
	}

	if len(masterKey) != masterKeyLen {
		return nil, fmt.Errorf("invalid key length: expected %d bytes, got %d", masterKeyLen, len(masterKey))
	}

	// Split master key (16-byte AES-128 key, 16-byte HMAC-SHA1 key)
	aesKey := masterKey[:16]
	hmacKey := masterKey[16:32]

	// Verify the correct password was provided via the (optional) sentinel
	if data.Sentinel != nil {
		if _, err := decryptEntry(*data.Sentinel, aesKey, hmacKey); err != nil {
			return nil, errors.New("SecureStore load failure: invalid key or password")
		}
	}

	return &SecretsManager{
		aesKey:  aesKey,
		hmacKey: hmacKey,
		secrets: data.Secrets,
	}, nil
}

// Get retrieves and decrypts a single named secret from the vault.
// Returns empty string and `ErrSecretNotFound` error if no such secret exists,
// returns empty string and the associated error upon decryption failure.
func (s *SecretsManager) Get(name string) (string, error) {
	entry, ok := s.secrets[name]
	if !ok {
		return "", ErrSecretNotFound
	}

	return decryptEntry(entry, s.aesKey, s.hmacKey)
}

// Keys retrieves a list of all keys in the vault.
func (s *SecretsManager) Keys() []string {
	keys := make([]string, 0, len(s.secrets))
	for k := range s.secrets {
		keys = append(keys, k)
	}
	return keys
}

func decryptEntry(entry vaultEntry, aesKey []byte, hmacKey []byte) (string, error) {
	iv, err := base64.StdEncoding.DecodeString(entry.IV)
	if err != nil {
		return "", fmt.Errorf("failed to decode IV: %w", err)
	}
	mac, err := base64.StdEncoding.DecodeString(entry.HMAC)
	if err != nil {
		return "", fmt.Errorf("failed to decode HMAC: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(entry.Payload)
	if err != nil {
		return "", fmt.Errorf("failed to decode payload: %w", err)
	}

	// Authenticate: HMAC(IV + Ciphertext)
	h := hmac.New(sha1.New, hmacKey)
	h.Write(iv)
	h.Write(ciphertext)
	computedMac := h.Sum(nil)

	if !hmac.Equal(mac, computedMac) {
		return "", errors.New("integrity check failed (HMAC mismatch)")
	}

	// Decrypt: AES-128-CBC
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS#7 unpadding
	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("secret decryption failed (padding): %w", err)
	}

	return string(unpadded), nil
}

func resolveMasterKey(source *KeySource, base64Salt string) ([]byte, error) {
	if source.keyType == typeKey {
		return source.value, nil
	}

	// Password-based derivation
	if base64Salt == "" {
		return nil, errors.New("vault missing root 'iv' (salt) required for password decryption")
	}

	salt, err := base64.StdEncoding.DecodeString(base64Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	return pbkdf2.Key(source.value, salt, pbkdf2Rounds, masterKeyLen, sha1.New), nil
}

// pkcs7Unpad validates and removes PKCS#7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid padding: data length is zero or not a multiple of block size")
	}

	padLen := int(data[length-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("invalid padding: pad length byte out of range")
	}

	// Verify all padding bytes are identical
	for i := 0; i < padLen; i++ {
		if data[length-1-i] != byte(padLen) {
			return nil, errors.New("invalid padding: inconsistent padding bytes")
		}
	}

	return data[:length-padLen], nil
}
