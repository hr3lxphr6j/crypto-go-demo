package main

import (
	"crypto/aes"
	"crypto/cipher"
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

func TestECBMode(t *testing.T) {
	var (
		key             = randomBytes(256 / 8)
		plaintext       = []byte("helloaes-256-ecbhelloaes-256-ecb")
		paddedPlaintext = padding(plaintext, aes.BlockSize)
		ciphertext      = make([]byte, len(paddedPlaintext))
	)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	c := NewECBEncrypter(block)
	c.CryptBlocks(ciphertext, paddedPlaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		c := NewECBDecrypter(block)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[1] += 1
		dec := make([]byte, len(ciphertext))
		c := NewECBDecrypter(block)
		c.CryptBlocks(dec, _enc)
		t.Logf("解密：%s\n", string(dec))
	})
}

func TestCBCMode(t *testing.T) {
	var (
		key             = randomBytes(256 / 8)
		iv              = randomBytes(aes.BlockSize)
		plaintext       = []byte("hello, aes-256-cbc, >>>>>, +++++, *****")
		paddedPlaintext = padding(plaintext, aes.BlockSize)
		ciphertext      = make([]byte, len(paddedPlaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	c := cipher.NewCBCEncrypter(block, iv)
	c.CryptBlocks(ciphertext, paddedPlaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		c := cipher.NewCBCDecrypter(block, iv)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		// 当前块（全部不可用）和下一块（对应位置）受影响
		_enc := sliceCopy(ciphertext)
		_enc[5] += 1
		dec := make([]byte, len(_enc))
		c := cipher.NewCBCDecrypter(block, iv)
		c.CryptBlocks(dec, _enc)
		t.Logf("解密：%s\n", string(dec))
	})

	t.Run("modify-single-byte-iv", func(t *testing.T) {
		// 篡改IV可以影响解密后第一块明文对应位置的结果
		dec := make([]byte, len(ciphertext))
		_iv := sliceCopy(iv)
		_iv[4] += 1
		c := cipher.NewCBCDecrypter(block, _iv)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
	})
}

func TestCFBMode(t *testing.T) {
	var (
		key        = randomBytes(256 / 8)
		iv         = randomBytes(aes.BlockSize)
		plaintext  = []byte("hello, aes-256-cfb, >>>>>, +++++, *****")
		ciphertext = make([]byte, len(plaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	s := cipher.NewCFBEncrypter(block, iv)
	s.XORKeyStream(ciphertext, plaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		s := cipher.NewCFBDecrypter(block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("明文：%s\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		// 当前块和下一块受影响
		_enc := sliceCopy(ciphertext)
		_enc[4+16] += 1
		res := make([]byte, len(_enc))
		s := cipher.NewCFBDecrypter(block, iv)
		s.XORKeyStream(res, _enc)
		t.Logf("解密：%s\n", string(res))
	})
}

func TestOFBMode(t *testing.T) {
	var (
		key        = randomBytes(256 / 8)
		iv         = randomBytes(aes.BlockSize)
		plaintext  = []byte("hello, aes-256-ofb, >>>>>, +++++, *****")
		ciphertext = make([]byte, len(plaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	s := cipher.NewOFB(block, iv)
	s.XORKeyStream(ciphertext, plaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		s := cipher.NewOFB(block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("明文：%s\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		// 仅当前位受影响
		_enc := sliceCopy(ciphertext)
		_enc[4] += 1
		res := make([]byte, len(_enc))
		s := cipher.NewOFB(block, iv)
		s.XORKeyStream(res, _enc)
		t.Logf("解密：%s\n", string(res))
	})
}

func TestCTRMode(t *testing.T) {
	var (
		key        = randomBytes(256 / 8)
		iv         = randomBytes(aes.BlockSize)
		plaintext  = []byte("hello, aes-256-ctr, >>>>>, +++++, *****")
		ciphertext = make([]byte, len(plaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(ciphertext, plaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		s := cipher.NewCTR(block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("明文：%s\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		// 仅当前位受影响
		_enc := sliceCopy(ciphertext)
		_enc[4+16] += 1
		res := make([]byte, len(_enc))
		s := cipher.NewCTR(block, iv)
		s.XORKeyStream(res, _enc)
		t.Logf("解密：%s\n", string(res))
	})
}
