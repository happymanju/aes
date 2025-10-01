package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func EncryptWithPassword(plaintext []byte, password []byte) (ciphertext []byte, err error) {
	h := sha256.New()
	h.Write(password)
	aesKey := h.Sum(nil)

	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("error making cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("error making gcm block: %w", err)
	}

	ciphertext = make([]byte, gcm.NonceSize())
	rand.Read(ciphertext)

	gcm.Seal(ciphertext, ciphertext, plaintext, nil)

	return ciphertext, nil
}

func DecryptWithPassword(ciphertext []byte, password []byte) (plaintext []byte, err error) {
	h := sha256.New()
	h.Write(password)
	aesKey := h.Sum(nil)

	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("error making aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("error making gcm block: %w", err)
	}

	nonce := ciphertext[0:gcm.NonceSize()]
	plaintext = make([]byte, 0)

	_, err = gcm.Open(plaintext, nonce, ciphertext[gcm.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ciphertext: %w", err)
	}

	return plaintext, nil
}

func Encrypt(plaintext []byte) (ciphertext []byte, aesKey []byte, err error) {
	aesKey = make([]byte, 32)

	rand.Read(aesKey)

	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error making cipher block from aes key: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, fmt.Errorf("error making gcm cipher: %w", err)
	}
	ciphertext = make([]byte, gcm.NonceSize())
	rand.Read(ciphertext)

	gcm.Seal(ciphertext, ciphertext, plaintext, nil)
	return ciphertext, aesKey, nil
}

func Decrypt(ciphertext []byte, aesKey []byte) (plaintext []byte, err error) {
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("error making aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("error making gcm block: %w", err)
	}

	plaintext = make([]byte, 0)

	plaintext, err = gcm.Open(plaintext, ciphertext[0:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	return plaintext, nil
}
