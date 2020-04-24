package address

import (
	"errors"
	"github.com/btcsuite/btcutil/base58"
)

// Address defines the address as string 
type Address struct {
	address string
}
// Base58 type defines the structure of an address legacy or wrapped segwit
type Base58 struct {
	Version byte
	Hash []byte
}

// Bech32 defines the structure of an address native segwit
type Bech32 struct {
	Version byte
	Prefix string
	Data []byte 
}

// Blech32 defines the structure of a confidential address native segwit
type Blech32 struct {
	Version byte
	PublicKey []byte
	Data []byte 
}

// FromBase58 decodes a string into a Base58 data structure
func FromBase58(address string) (*Base58, error) {
	decoded, version, err := base58.CheckDecode(address)
	if err != nil {
		return nil, errors.New("Invalid address")
	}

	if len(decoded) < 20 {
		return nil, errors.New(address + " is too short")
	}
	if len(decoded) > 20 {
		return nil, errors.New(address + " is too long")
	}

	return &Base58{version,decoded}, nil
}