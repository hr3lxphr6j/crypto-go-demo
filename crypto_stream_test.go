package main

import (
	"crypto/rc4"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func doRC4(key, in []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	dst := make([]byte, len(in))
	c.XORKeyStream(dst, in)
	return dst
}

func TestRC4(t *testing.T) {
	var (
		key        = randomBytes(256)
		plaintext  = []byte("hello, rc4")
		ciphertext = doRC4(key, plaintext)
	)

	t.Run("decrypt", func(t *testing.T) {
		// 解密
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", string(doRC4(key, ciphertext)))
	})

	// 修改密文的一位查看影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[1] += 1
		t.Logf("解密：%s\n", string(doRC4(key, _enc)))
	})

	// 已知明文不知道密码的情况下篡改解密后的内容
	t.Run("modify-plaintext", func(t *testing.T) {
		/**
		C：密文
		P：明文
		P': 要篡改的目标明文
		K：Key
		Fn：加密算法

		已知：
		C = P xor Fn(K)
		P = C xor Fn(K)
		diff = P xor P'

		所以：
		P' = diff xor P
		P' = diff xor C xor Fn(K)
		*/
		// 计算要修改内容与明文的不同
		diff := xor(plaintext, []byte("bingo, win"))
		// 对密文进行修改
		patch := xor(diff, ciphertext)
		t.Logf("已知原文情况对密文进行修改：%s\n", string(doRC4(key, patch)))
	})
}

func doChacha20(key, nonce, in []byte) []byte {
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	res := make([]byte, len(in))
	c.XORKeyStream(res, in)
	return res
}

func TestChacha20(t *testing.T) {
	var (
		key        = randomBytes(chacha20.KeySize)
		nonce      = randomBytes(chacha20.NonceSize)
		plaintext  = []byte("hello, chacha20")
		ciphertext = doChacha20(key, nonce, plaintext)
	)

	t.Run("decrypt", func(t *testing.T) {
		// 解密
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", string(doChacha20(key, nonce, ciphertext)))
	})

	// 修改密文的一位查看影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[0] += 1
		t.Logf("解密：%s\n", string(doChacha20(key, nonce, _enc)))
	})
}
