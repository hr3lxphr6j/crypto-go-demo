package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestAesGcm(t *testing.T) {
	var (
		key               = randomBytes(256 / 8)
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
		if err != nil {
			t.Fatalf("解密错误: %v", err)
		}
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[0] += 1
		if _, err := aead.Open(nil, nonce, _enc, nil); err != nil {
			t.Logf("解密错误: %v", err)
		}
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
		if err != nil {
			t.Fatalf("解密错误：%v", err)
		}
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("原文：%s\n", string(res))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[0] += 1
		if _, err := aead.Open(nil, nonce, _enc, nil); err != nil {
			t.Logf("解密错误: %v", err)
		}
	})
}
