package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"testing"
)

func padding(in []byte, blockSize int) []byte {
	if len(in) <= blockSize {
		return in
	}
	count := len(in) / blockSize
	if len(in)%blockSize > 0 {
		count += 1
	}
	dst := make([]byte, count*blockSize)
	copy(dst, in)
	return dst
}

func TestCBCMode(t *testing.T) {
	var (
		key  = random(256 / 8)       // init key
		iv   = random(aes.BlockSize) // init iv
		plan = []byte("hello, aes-256-cbc, >>>>>, +++++, *****")
	)

	// init aes
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("failed to init aes block, err: %v", err)
	}

	// init cbc mode
	bm := cipher.NewCBCEncrypter(block, iv)

	// Encrypt
	padded := padding(plan, aes.BlockSize)
	enc := make([]byte, len(padded))
	bm.CryptBlocks(enc, padded)

	// Decrypt
	t.Run("decrypt", func(t *testing.T) {
		bmd := cipher.NewCBCDecrypter(block, iv)
		res := make([]byte, len(enc))
		bmd.CryptBlocks(res, enc)
		fmt.Printf("密文：%x\n", enc)
		fmt.Printf("解密：%s\n", string(res))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(enc)
		_enc[4] += 1
		bmd := cipher.NewCBCDecrypter(block, iv)
		res := make([]byte, len(_enc))
		bmd.CryptBlocks(res, _enc)
		fmt.Printf("解密：%s\n", string(res))
	})
}

func TestCFBMode(t *testing.T) {
	var (
		key  = random(256 / 8)       // init key
		iv   = random(aes.BlockSize) // init iv
		plan = []byte("hello, aes-256-cfb, >>>>>, +++++, *****")
	)

	// init aes
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("failed to init aes block, err: %v", err)
	}

	// init cfb mode
	s := cipher.NewCFBEncrypter(block, iv)
	// Encrypt
	enc := make([]byte, len(plan))
	s.XORKeyStream(enc, plan)

	t.Run("decrypt", func(t *testing.T) {
		s := cipher.NewCFBDecrypter(block, iv)
		dec := make([]byte, len(enc))
		s.XORKeyStream(dec, enc)
		t.Logf("密文：%x\n", enc)
		t.Logf("明文：%s\n", string(dec))
	})
}

func TestOFBMode(t *testing.T) {
	var (
		key  = random(256 / 8)       // init key
		iv   = random(aes.BlockSize) // init iv
		plan = []byte("hello, aes-256-ofb, >>>>>, +++++, *****")
	)

	// init aes
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("failed to init aes block, err: %v", err)
	}

	// init ofb mode
	s := cipher.NewOFB(block, iv)
	// Encrypt
	enc := make([]byte, len(plan))
	s.XORKeyStream(enc, plan)

	t.Run("decrypt", func(t *testing.T) {
		s := cipher.NewOFB(block, iv)
		dec := make([]byte, len(enc))
		s.XORKeyStream(dec, enc)
		t.Logf("密文：%x\n", enc)
		t.Logf("明文：%s\n", string(dec))
	})
}

func TestCTRMode(t *testing.T) {
	var (
		key  = random(256 / 8)       // init key
		iv   = random(aes.BlockSize) // init iv
		plan = []byte("hello, aes-256-ctr, >>>>>, +++++, *****")
	)

	// init aes
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("failed to init aes block, err: %v", err)
	}

	// init ctr mode
	s := cipher.NewCTR(block, iv)
	// Encrypt
	enc := make([]byte, len(plan))
	s.XORKeyStream(enc, plan)

	t.Run("decrypt", func(t *testing.T) {
		s := cipher.NewCTR(block, iv)
		dec := make([]byte, len(enc))
		s.XORKeyStream(dec, enc)
		t.Logf("密文：%x\n", enc)
		t.Logf("明文：%s\n", string(dec))
	})
}
