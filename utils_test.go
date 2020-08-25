package main

import (
	"crypto/rand"
)

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("length not equal")
	}
	dst := make([]byte, len(a))
	for idx, c := range a {
		dst[idx] = c ^ b[idx]
	}
	return dst
}

func random(n int) []byte {
	if n < 0 {
		panic("slice size must bigger than zero")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func sliceCopy(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}
