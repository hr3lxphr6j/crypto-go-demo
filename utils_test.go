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

func randomBytes(n int) []byte {
	if n < 0 {
		panic("Slice size must be greater than zero")
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
