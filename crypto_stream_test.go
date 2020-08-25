package main

import (
	"crypto/rc4"
	"testing"
)

func doRC4Enc(key, in []byte) []byte {
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
		key  = random(256)          // 初始化密钥
		text = []byte("hello, rc4") // 明文
		enc  = doRC4Enc(key, text)  // 密文
	)

	t.Run("decrypt", func(t *testing.T) {
		// 解密
		t.Logf("密文：%x\n", enc)
		t.Logf("解密：%s\n", string(doRC4Enc(key, enc)))
	})

	// 修改密文的一位查看影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(enc)
		_enc[1] += 1
		t.Logf("解密：%s\n", string(doRC4Enc(key, _enc)))
	})

	// 重放攻击
	t.Run("CCA", func(t *testing.T) {

	})

	// 已知明文不知道密码的情况下篡改解密后的内容
	t.Run("modify-plain-text", func(t *testing.T) {
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
		diff := xor(text, []byte("bingo, win"))
		// 对密文进行修改
		patch := xor(diff, enc)
		t.Logf("已知原文情况对密文进行修改：%s\n", string(doRC4Enc(key, patch)))
	})
}
