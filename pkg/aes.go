package pkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"io"
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
func WriteCiphertextToPEM(w io.Writer, ciphertext []byte) error {
	p := pem.Block{
		Type:  "CIPHERTEXT",
		Bytes: ciphertext,
	}
	err := pem.Encode(w, &p)
	if err != nil {
		return err
	}

	return nil
}

// decode from PEM
func ReadFromPEM(r io.Reader) ([]byte, error) {
	b := bytes.Buffer{}

	_, err := io.Copy(&b, r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b.Bytes())
	return block.Bytes, nil
}

// encode key to PEM
func WriteKeyToPEM(w io.Writer, key []byte) error {
	p := pem.Block{
		Type:  "SYMMETRIC KEY",
		Bytes: key,
	}
	err := pem.Encode(w, &p)
	if err != nil {
		return err
	}
	return nil
}

// decode key from PEM
func ReadKeyFromPEM(r io.Reader) ([]byte, error) {
	b := bytes.Buffer{}

	_, err := io.Copy(&b, r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b.Bytes())
	return block.Bytes, nil
}
