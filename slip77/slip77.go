package slip77

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/btcsuite/btcd/btcec"
)

var (
	domain = []byte("Symmetric key seed")
	label  = []byte("SLIP-0077")
	prefix = byte(0)
)

//Slip77 holds the Master Blinding Key
type Slip77 struct {
	MasterKey []byte
}

//KeyPair holds a *btcec.PrivateKey and a *btcec.PublicKey
type KeyPair struct {
	PrivateKey *btcec.PrivateKey
	PublicKey  *btcec.PublicKey
}

// FromMasterKey sets the provided master key to the returned instance of Slip77
func FromMasterKey(masterKey []byte) (*Slip77, error) {
	if masterKey == nil || len(masterKey) <= 0 {
		return nil, errors.New("invalid master key")
	}

	return &Slip77{
		MasterKey: masterKey,
	}, nil
}

// FromSeed derives the master key from the given seed and uses it to create
// and return a new Slip77 instance
func FromSeed(seed []byte) (*Slip77, error) {
	if seed == nil || len(seed) <= 0 {
		return nil, errors.New("invalid seed")
	}

	hmacRoot := hmac.New(sha512.New, domain)
	hmacRoot.Write(seed)
	root := hmacRoot.Sum(nil)

	hmacMasterKey := hmac.New(sha512.New, root[:32])
	hmacMasterKey.Write([]byte{prefix})
	hmacMasterKey.Write(label)
	masterKey := hmacMasterKey.Sum(nil)

	return FromMasterKey(masterKey[32:])
}

// DeriveKey derives a private key from the master key of the Slip77 type
// and a provided script
func (s *Slip77) DeriveKey(script []byte) (*KeyPair, error) {
	if s.MasterKey == nil || len(s.MasterKey) <= 0 {
		return nil, errors.New("master key must be defined")
	}
	if script == nil || len(script) <= 0 {
		return nil, errors.New("invalid script")
	}

	hmacKey := hmac.New(sha256.New, s.MasterKey)
	hmacKey.Write(script)
	key := hmacKey.Sum(nil)

	privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), key)

	return &KeyPair{privateKey, publicKey}, nil
}
