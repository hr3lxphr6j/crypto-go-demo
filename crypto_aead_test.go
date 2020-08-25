package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestChacha20Poly1305(t *testing.T) {
	var (
		key      = random(chacha20poly1305.KeySize)   // 初始化密钥
		nonce    = random(chacha20poly1305.NonceSize) // 初始化nonce
		planText = []byte("Hello, Chacha20-ploy1305")
	)

	// 加密
	c, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatalln(err)
	}
	enc := c.Seal(nil, nonce, planText, nil)

	// 解密
	t.Run("decrypt", func(t *testing.T) {
		c, err := chacha20poly1305.New(key)
		if err != nil {
			log.Fatalln(err)
		}
		res, err := c.Open(nil, nonce, enc, nil)
		if err != nil {
			t.Fatalf("解密错误：%v", err)
		}
		fmt.Printf("密文：%x\n", enc)
		fmt.Printf("原文：%s\n", string(res))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(enc)
		c, err := chacha20poly1305.New(key)
		if err != nil {
			log.Fatalln(err)
		}
		_enc[0] += 1
		if _, err := c.Open(nil, nonce, _enc, nil); err != nil {
			t.Logf("解密错误: %v", err)
		}
	})
}

func TestAesGcm(t *testing.T) {
	var (
		key       = random(256 / 8)
		plainText = []byte("hello aes-256-gcm")
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to init aes block, err: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to init gcm mode, err: %v", err)
	}
	nonce := random(aead.NonceSize())
	// 加密
	enc := aead.Seal(nil, nonce, plainText, nil)

	t.Run("decrypt", func(t *testing.T) {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("failed to init gcm mode, err: %v", err)
		}
		dec, err := aead.Open(nil, nonce, enc, nil)
		if err != nil {
			t.Fatalf("failed to decrypt err: %v", err)
		}
		t.Logf("密文：%x\n", enc)
		t.Logf("解密：%s\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(enc)
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("failed to init gcm mode, err: %v", err)
		}
		_enc[0] += 1
		if _, err := aead.Open(nil, nonce, _enc, nil); err != nil {
			t.Logf("解密错误: %v", err)
		}
	})
}
