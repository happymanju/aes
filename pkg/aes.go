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
	if err != nil {
		return nil, fmt.Errorf("error sealing with gcm: %w", err)
	}
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
