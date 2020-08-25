package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

func TestAesGcm(t *testing.T) {
	var (
		key               = pbkdf2.Key([]byte("pwd"), randomBytes(16), 1<<16, 256/8, sha512.New)
		plaintext         = []byte("hello aes-256-gcm")
		nonce, ciphertext []byte
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce = randomBytes(aead.NonceSize())
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)

	t.Run("decrypt", func(t *testing.T) {
		dec, err := aead.Open(nil, nonce, ciphertext, nil)
		assert.NoError(t, err)
		assert.Equal(t, dec, plaintext)
	})

	t.Run("modify-ciphertext", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[0] += 1
		_, err := aead.Open(nil, nonce, _enc, nil)
		assert.EqualError(t, err, "cipher: message authentication failed")
	})
}

func TestChacha20Poly1305(t *testing.T) {
	var (
		key        = randomBytes(chacha20poly1305.KeySize)
		nonce      = randomBytes(chacha20poly1305.NonceSize)
		plaintext  = []byte("Hello, Chacha20-ploy1305")
		ciphertext []byte
	)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatalln(err)
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)

	t.Run("decrypt", func(t *testing.T) {
		res, err := aead.Open(nil, nonce, ciphertext, nil)
		assert.NoError(t, err)
		assert.Equal(t, res, plaintext)
	})

	t.Run("modify-ciphertext", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[0] += 1
		_, err := aead.Open(nil, nonce, _enc, nil)
		assert.EqualError(t, err, "chacha20poly1305: message authentication failed")
	})
}
