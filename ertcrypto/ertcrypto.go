// Package ertcrypto provides cryptographic functionalities for Go enclaves
package ertcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/edgelesssys/ertgolib/ertenclave"
)

// Encrypt encrypts a given plaintext with a supplied key using AES-GCM
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Get cipher object with key
	aesgcm, err := getCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt data
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a given ciphertext (with prepended nonce) with a supplied key using AES-GCM
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Get cipher object with key
	aesgcm, err := getCipher(key)
	if err != nil {
		return nil, err
	}

	// Split ciphertext into nonce & actual data
	if len(ciphertext) < aesgcm.NonceSize() {
		return nil, fmt.Errorf("nonce is too short")
	}
	nonce, encryptedData := ciphertext[:aesgcm.NonceSize()], ciphertext[aesgcm.NonceSize():]

	// Decrypt data
	plaintext, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SealWithUniqueKey encrypts a given plaintext with a key derived from a measurement of the enclave.
func SealWithUniqueKey(plaintext []byte) ([]byte, error) {
	sealKey, keyInfo, err := ertenclave.GetUniqueSealKey()
	if err != nil {
		return nil, err
	}

	return seal(plaintext, sealKey, keyInfo)
}

// SealWithProductKey encrypts a given plaintext with the a key from the signer and product id of the enclave.
func SealWithProductKey(plaintext []byte) ([]byte, error) {
	sealKey, keyInfo, err := ertenclave.GetProductSealKey()
	if err != nil {
		return nil, err
	}

	return seal(plaintext, sealKey, keyInfo)
}

// Unseal decrypts data encrypted with the unique or product CPU key with the help of the embedded key info
func Unseal(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 4 {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	keyInfoLength := binary.LittleEndian.Uint32(ciphertext[:4])

	// We might deal with invalid user data as input, so let's convert an potential upcoming out-of-bounds panic to an error the underlying caller can choose how to deal with this situation.
	if keyInfoLength == 0 || 4+int(keyInfoLength) > len(ciphertext) {
		return nil, fmt.Errorf("embedded length information does not fit the given ciphertext")
	}

	keyInfo := ciphertext[4 : 4+keyInfoLength]
	ciphertext = ciphertext[4+keyInfoLength:]

	sealKey, err := ertenclave.GetSealKey(keyInfo)
	if err != nil {
		return nil, err
	}

	return Decrypt(ciphertext, sealKey)
}

func getCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(plaintext []byte, sealKey []byte, keyInfo []byte) ([]byte, error) {
	// Encrypt plaintext with the given seal key
	ciphertext, err := Encrypt(plaintext, sealKey)
	if err != nil {
		return nil, err
	}

	// Encode keyInfo and its length and append it in front of the ciphertext
	// Use a fixed size length so we can properly extract the length from the ciphertext when unsealing
	keyInfoLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyInfoLength, uint32(len(keyInfo)))
	keyInfoEncoded := append(keyInfoLength, keyInfo...)

	return append(keyInfoEncoded, ciphertext...), nil
}
