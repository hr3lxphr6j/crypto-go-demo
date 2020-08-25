package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestECDSA(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello ecdsa")
	hash := sha256.New().Sum(msg)
	r, s, err := ecdsa.Sign(rand.Reader, pk, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("verify", func(t *testing.T) {
		t.Logf("Verify result: %v", ecdsa.Verify(&pk.PublicKey, hash, r, s))
	})
}

func TestED25519(t *testing.T) {
	pubKey, priKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello ed25519")
	sign := ed25519.Sign(priKey, msg)
	t.Run("verify", func(t *testing.T) {
		t.Logf("Verify result: %v", ed25519.Verify(pubKey, msg, sign))
	})
}
