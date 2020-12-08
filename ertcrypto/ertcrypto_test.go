package ertcrypto

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptAndDecrypt(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Test parameters
	encryptionKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	testString := "Edgeless"

	// Encrypt text
	ciphertext, err := Encrypt([]byte(testString), encryptionKey)
	require.NoError(err)

	// Decrypt text
	plaintext, err := Decrypt(ciphertext, encryptionKey)
	require.NoError(err)
	assert.EqualValues(testString, plaintext)
}

func TestSeal(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Test parameters
	sealKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	keyInfo := []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 42, 42, 42}
	testString := "Edgeless"

	// Seal with the given parameters
	sealedText, err := seal([]byte(testString), sealKey, keyInfo)
	require.NoError(err)

	// Check structure of the sealed data
	keyInfoLength := sealedText[:4]
	actualKeyInfoLength := binary.LittleEndian.Uint32(keyInfoLength)
	assert.EqualValues(len(keyInfo), actualKeyInfoLength)

	// Check if keyInfo was written correctly and is at the correct position
	actualKeyInfo := sealedText[4 : 4+len(keyInfo)]
	assert.Equal(keyInfo, actualKeyInfo)

	// Check if ciphertext can be decrypted correctly
	ciphertext := sealedText[4+len(keyInfo):]
	plaintext, err := Decrypt(ciphertext, sealKey)
	require.NoError(err)
	assert.EqualValues(testString, plaintext)
}
