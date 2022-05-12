package descriptor

import (
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/ripemd160"
)

func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

func hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}
