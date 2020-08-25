package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/pbkdf2"
)

// 块密码，顾名思义其一次只能加密一个固定长度的密文，也就是一个块。
// 比如AES就是的块长度就是128Bit，一次只能加密16字节。
// 当然我们要加密的数据不可能只有16字节，所以就需要使用以下这些块密码工作模式。

// 这里主要使用AES-256来展示块加密的工作模式，其他块加密算法（实现 cipher.Block 接口）同理。

func TestECBMode(t *testing.T) {
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
	// ECB模式下如果明文的块相同，密文块也会相同，因此它不能很好地隐藏数据模式。
	// 在go的官方包中并没有提供可用ECB库，为了演示ECB的性质，我找了个开源的ECB实现（参见ecb.go）
	var (
		key = pbkdf2.Key([]byte("pwd"), randomBytes(16), 1<<16, 256/8, sha512.New)
		// 这个密文长度为 16 + 16 + 16 + 15，会被分为四个块，其中第一个和第三个块的明文是相同的，都为 helloaes-256-ecb，
		// 最后一个块长度不够 16 字节，需要填充到 16 字节。
		plaintext       = []byte("helloaes-256-ecbAAAABBBBCCCCDDDDhelloaes-256-ecbDDDDCCCCBBBBAAA")
		paddedPlaintext = padding(plaintext, aes.BlockSize)
		ciphertext      = make([]byte, len(paddedPlaintext))
	)
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)
	// 注意这里返回的对象实现了 cipher.BlockMode 接口
	c := NewECBEncrypter(block)
	c.CryptBlocks(ciphertext, paddedPlaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		c := NewECBDecrypter(block)
		c.CryptBlocks(dec, ciphertext)
		assert.EqualValues(t, plaintext, dec[:63])
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", string(dec))
		assert.Equal(t, dec[:16], dec[32:48])
		t.Logf("> 可以看到第一个块的加密结果和第三个块是相同的")
		t.Logf("> 解密后的内容包含 PADDING 的内容，在返回给应用层前要注意将其去掉")
	})

	// 使用错误的 key
	t.Run("bad-key", func(t *testing.T) {
		_key := sliceCopy(key)
		_key[0] += 1
		_block, _ := aes.NewCipher(_key)
		dec := make([]byte, len(ciphertext))
		c := NewECBDecrypter(_block)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> key错误的情况下解密不会出现程序错误，只不过解密的出来的东西是乱码")
	})

	// 修改密文的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		// 修改密文第二个块中的一个字节
		_enc[18] += 1
		dec := make([]byte, len(ciphertext))
		c := NewECBDecrypter(block)
		c.CryptBlocks(dec, _enc)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> 解密本身不会出现程序错误，由于修改了第二个块的密文，在解密后二个块的内容为乱码")
	})

	// 对密文分组重新排序后解密，查看对解密后的明文的影响
	t.Run("reorder", func(t *testing.T) {
		_enc := make([]byte, len(ciphertext))
		// 将密文块倒序排列
		copy(_enc[:16], ciphertext[48:])
		copy(_enc[16:32], ciphertext[32:48])
		copy(_enc[32:48], ciphertext[16:32])
		copy(_enc[48:], ciphertext[:16])
		dec := make([]byte, len(ciphertext))
		c := NewECBDecrypter(block)
		c.CryptBlocks(dec, _enc)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> 可以看到，解密后的内容也发生块的倒序，攻击者可以在不知道密码的情况下修改密文从而影响明文")
	})
}

func TestCBCMode(t *testing.T) {
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
	// CBC 模式需要 IV，IV 的长度是 aes 的块长度（16 Byte），IV 可以明文存储，但每次加密都需要重新生成
	var (
		key             = pbkdf2.Key([]byte("pwd"), randomBytes(16), 1<<16, 256/8, sha512.New)
		iv              = randomBytes(aes.BlockSize)
		plaintext       = []byte("helloaes-256-cbcAAAABBBBCCCCDDDDhelloaes-256-cbcDDDDCCCCBBBBAAA")
		paddedPlaintext = padding(plaintext, aes.BlockSize)
		ciphertext      = make([]byte, len(paddedPlaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	// 注意这里返回的对象也实现了 cipher.BlockMode 接口
	c := cipher.NewCBCEncrypter(block, iv)
	c.CryptBlocks(ciphertext, paddedPlaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		c := cipher.NewCBCDecrypter(block, iv)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> 和 ECB 模式不同，相同的明文不会导致出现相同的密文。但如果对相同的明文选择使用同样的 IV 也会让密文相同")
		t.Logf("> 解密后的内容包含 PADDING 的内容，在返回给应用层前要注意将其去掉")
	})

	// 使用错误的 key
	t.Run("bad-key", func(t *testing.T) {
		_key := sliceCopy(key)
		_key[0] += 1
		_block, _ := aes.NewCipher(_key)
		dec := make([]byte, len(ciphertext))
		c := cipher.NewCBCDecrypter(_block, iv)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> key错误的情况下解密不会出现程序错误，只不过解密的出来的东西是乱码")
	})

	// 修改密文的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[21] += 3
		dec := make([]byte, len(_enc))
		c := cipher.NewCBCDecrypter(block, iv)
		c.CryptBlocks(dec, _enc)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> 当前块全部乱码，下一块的对应位置受影响")
	})

	// 修改 IV 的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte-iv", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		_iv := sliceCopy(iv)
		_iv[4] += 1
		c := cipher.NewCBCDecrypter(block, _iv)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf(">  篡改IV可以影响解密后第一块明文对应位置的结果")
	})

	// 使用完全错误的IV，查看对解密后的明文的影响
	t.Run("wrong-iv", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		_iv := make([]byte, aes.BlockSize)
		c := cipher.NewCBCDecrypter(block, _iv)
		c.CryptBlocks(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> 只有第一个分组是乱码，后续正常")
	})
}

func TestCFBMode(t *testing.T) {
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
	// CFB 模式同样需要 IV，与 CBC 不同的是 CFB 下不需要 PADDING。
	// CFB 的密文是明文与一个东西（加密上个块的密文） XOR 出来的。
	var (
		key        = pbkdf2.Key([]byte("pwd"), randomBytes(16), 1<<16, 256/8, sha512.New)
		iv         = randomBytes(aes.BlockSize)
		plaintext  = []byte("helloaes-256-cfbAAAABBBBCCCCDDDDhelloaes-256-cfbDDDDCCCCBBBBAAA")
		ciphertext = make([]byte, len(plaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	// 注意这里返回的对象实现的接口是 cipher.Stream，与 ECB 和 CBC 模式不同。
	// ECB 和 CBC 模式需要将加密和解密的内容全部加载到内存中，
	// 而 CFB 返回的 cipher.Stream 可以放到 cipher.StreamWriter, cipher.StreamReader 里，
	// 作为 io.Writer, io.Reader 流式加/解密大负载
	s := cipher.NewCFBEncrypter(block, iv)
	s.XORKeyStream(ciphertext, plaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		s := cipher.NewCFBDecrypter(block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("明文：%s\n", string(dec))
	})

	// 使用错误的 key
	t.Run("bad-key", func(t *testing.T) {
		_key := sliceCopy(key)
		_key[0] += 1
		dec := make([]byte, len(ciphertext))
		_block, _ := aes.NewCipher(_key)
		s := cipher.NewCFBDecrypter(_block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> key错误的情况下解密不会出现程序错误，只不过解密的出来的东西是乱码")
	})

	// 修改密文的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[21] += 1
		res := make([]byte, len(_enc))
		s := cipher.NewCFBDecrypter(block, iv)
		s.XORKeyStream(res, _enc)
		t.Logf("解密：%s\n", string(res))
		t.Logf("> 当前块对应位受影响，下一个块乱码")
	})

	// 修改 IV 的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte-iv", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		_iv := sliceCopy(iv)
		_iv[4] += 1
		c := cipher.NewCFBDecrypter(block, _iv)
		c.XORKeyStream(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf(">  篡改IV只影响第一个分组")
	})
}

func TestOFBMode(t *testing.T) {
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
	// 和 CFB 类似，OFB 的密钥来自与明文与密钥流 XOR 的结果，完全是流密码的行为
	var (
		key        = pbkdf2.Key([]byte("pwd"), randomBytes(16), 1<<16, 256/8, sha512.New)
		iv         = randomBytes(aes.BlockSize)
		plaintext  = []byte("helloaes-256-ofbAAAABBBBCCCCDDDDhelloaes-256-ofbDDDDCCCCBBBBAAA")
		ciphertext = make([]byte, len(plaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	// 和 CFB 一样，返回的对象实现了 cipher.Stream 接口
	s := cipher.NewOFB(block, iv)
	// 因为是彻底的流密码，所以加密和解密的行为是相同的
	s.XORKeyStream(ciphertext, plaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		s := cipher.NewOFB(block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("明文：%s\n", string(dec))
	})

	// 使用错误的 key
	t.Run("bad-key", func(t *testing.T) {
		_key := sliceCopy(key)
		_key[0] += 1
		dec := make([]byte, len(ciphertext))
		_block, _ := aes.NewCipher(_key)
		s := cipher.NewOFB(_block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> key错误的情况下解密不会出现程序错误，只不过解密的出来的东西是乱码")
	})

	// 修改密文的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[4] += 1
		res := make([]byte, len(_enc))
		s := cipher.NewOFB(block, iv)
		s.XORKeyStream(res, _enc)
		t.Logf("解密：%s\n", string(res))
		t.Logf("> 和流密码行为相同，修改密文仅影响当前明文的对应位置")
	})

	// 修改 IV 的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte-iv", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		_iv := sliceCopy(iv)
		_iv[4] += 1
		c := cipher.NewOFB(block, _iv)
		c.XORKeyStream(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf(">  生成的密钥流是错误的，全部分组都会乱码")
	})
}

func TestCTRMode(t *testing.T) {
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
	// 和 OFB 类似，CTR 也是通过块加密生成密钥流，拥有流密码的特性
	var (
		key        = pbkdf2.Key([]byte("pwd"), randomBytes(16), 1<<16, 256/8, sha512.New)
		iv         = randomBytes(aes.BlockSize)
		plaintext  = []byte("helloaes-256-ctrAAAABBBBCCCCDDDDhelloaes-256-ctrDDDDCCCCBBBBAAA")
		ciphertext = make([]byte, len(plaintext))
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	// 和 OFB 一样，返回的对象实现了 cipher.Stream 接口，加密和解密的行为是相同的。
	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(ciphertext, plaintext)

	t.Run("decrypt", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		s := cipher.NewCTR(block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("明文：%s\n", string(dec))
	})

	// 使用错误的 key
	t.Run("bad-key", func(t *testing.T) {
		_key := sliceCopy(key)
		_key[0] += 1
		dec := make([]byte, len(ciphertext))
		_block, _ := aes.NewCipher(_key)
		s := cipher.NewCTR(_block, iv)
		s.XORKeyStream(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf("> key错误的情况下解密不会出现程序错误，只不过解密的出来的东西是乱码")
	})

	// 修改密文的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[4] += 1
		res := make([]byte, len(_enc))
		s := cipher.NewCTR(block, iv)
		s.XORKeyStream(res, _enc)
		t.Logf("解密：%s\n", string(res))
		t.Logf("> 和流密码行为相同，修改密文仅影响当前明文的对应位置")
	})

	// 修改 IV 的一位，查看对解密后的明文的影响
	t.Run("modify-single-byte-iv", func(t *testing.T) {
		dec := make([]byte, len(ciphertext))
		_iv := sliceCopy(iv)
		_iv[4] += 1
		c := cipher.NewCTR(block, _iv)
		c.XORKeyStream(dec, ciphertext)
		t.Logf("解密：%s\n", string(dec))
		t.Logf(">  生成的密钥流是错误的，全部分组都会乱码")
	})
}
