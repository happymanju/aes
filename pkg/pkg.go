package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// gen aes key
func AESKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Reader.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func EncryptWithAES(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Reader.Read(nonce)

	gcm.Seal(nonce, nonce, plaintext, nil)
	return nonce, nil
}

// decrypt with aes key
func DecryptWithAES(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, ciphertext[:32])

	plaintext := make([]byte, 0)

	_, err = gcm.Open(plaintext, nonce, ciphertext[32:], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil

}

// encode to PEM
// decode from PEM
// encode key to PEM
// decode key from PEM
//
