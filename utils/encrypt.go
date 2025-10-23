package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Encrypt plaintext using AES-256-GCM.
// The key must be a base64-encoded 32-byte value (44 characters in base64).
func Encrypt(plaintext, key string) (string, error) {
	if key == "" {
		return "", errors.New("missing encryption key")
	}

	// Decode the base64 key into 32 raw bytes
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 encryption key")
	}
	if len(k) != 32 {
		return "", errors.New("encryption key must be 32 bytes after base64 decoding")
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt ciphertext using AES-256-GCM.
func Decrypt(ciphertext, key string) (string, error) {
	if key == "" {
		return "", errors.New("missing decryption key")
	}

	// Decode the base64 key into raw bytes
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 decryption key")
	}
	if len(k) != 32 {
		return "", errors.New("decryption key must be 32 bytes after base64 decoding")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("invalid ciphertext")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
