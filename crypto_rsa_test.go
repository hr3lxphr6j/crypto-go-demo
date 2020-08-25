package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"log"
	"testing"
)

func TestRSAOAEP(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("E: %v\nD: %v\nN: %v\n", pk.E, pk.D, pk.N)

	plaintext := []byte{0x00, 0x00, 0x00, 0x01}
	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, &pk.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("decrypt", func(t *testing.T) {
		dec, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, pk, ciphertext, nil)
		if err != nil {
			t.Fatalf("解密失败：%v", err)
		}
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%x\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[0] += 1
		if _, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, pk, _enc, nil); err != nil {
			t.Logf("解密失败：%v", err)
		}
	})
}

func TestRSAPKCS1v15(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("E: %v\nD: %v\nN: %v\n", pk.E, pk.D, pk.N)
	plaintext := []byte{0x00, 0x00, 0x00, 0x01}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &pk.PublicKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("decrypt", func(t *testing.T) {
		dec, err := rsa.DecryptPKCS1v15(rand.Reader, pk, ciphertext)
		if err != nil {
			t.Fatalf("解密失败：%v", err)
		}
		t.Logf("密文：%x\n", ciphertext)
		t.Logf("解密：%x\n", string(dec))
	})

	t.Run("modify-single-byte", func(t *testing.T) {
		_enc := sliceCopy(ciphertext)
		_enc[0] += 1
		if _, err := rsa.DecryptPKCS1v15(rand.Reader, pk, _enc); err != nil {
			t.Logf("解密失败：%v", err)
		}
	})
}

func TestRSASignPSS(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("E: %v\nD: %v\nN: %v\n", pk.E, pk.D, pk.N)

	msg := []byte{0x00, 0x00, 0x00, 0x01}
	hash := sha512.New()
	hash.Sum(msg)
	sum := hash.Sum(nil)
	sign, err := rsa.SignPSS(rand.Reader, pk, crypto.SHA512, sum, &rsa.PSSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("verify", func(t *testing.T) {
		log.Print(rsa.VerifyPSS(&pk.PublicKey, crypto.SHA512, sum, sign, &rsa.PSSOptions{}))
	})
}

func TestRSASignPKCS1v15(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("E: %v\nD: %v\nN: %v\n", pk.E, pk.D, pk.N)

	msg := []byte{0x00, 0x00, 0x00, 0x01}
	hash := sha512.New()
	hash.Sum(msg)
	sum := hash.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA512, sum)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("verify", func(t *testing.T) {
		log.Print(rsa.VerifyPKCS1v15(&pk.PublicKey, crypto.SHA512, sum, sign))
	})
}
