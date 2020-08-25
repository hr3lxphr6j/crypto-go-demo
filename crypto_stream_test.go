package main

import (
	"crypto/rc4"
	"testing"

	"github.com/stretchr/testify/assert"
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
	// https://en.wikipedia.org/wiki/RC4
	// RC4的安全性已经不满足当前的需求，这个只是展示流密码的一些性质
	var (
		key        = randomBytes(256)
		plaintext  = []byte("hello, rc4")
		ciphertext = doRC4(key, plaintext)
	)

	// 解密
	t.Run("decrypt", func(t *testing.T) {
		res := string(doRC4(key, ciphertext))
		assert.EqualValues(t, plaintext, res)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", res)
	})

	// 修改密文的一位查看影响
	t.Run("modify-ciphertext", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		// 修改密文的第二字节
		_enc[1] += 1
		t.Logf("解密：%s\n", string(doRC4(key, _enc)))
		t.Logf("> 解密本身不会发生错误，对密文的修改会影响对应的明文")
	})

	// 已知明文不知道密码的情况下篡改解密后的内容
	t.Run("modify-plaintext-by-attack-ciphertext", func(t *testing.T) {
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
