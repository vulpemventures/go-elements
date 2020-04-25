package address

import (
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/bech32"
	
)

// Address defines the address as string 
type Address struct {
	address string
}
// Base58 type defines the structure of an address legacy or wrapped segwit
type Base58 struct {
	Version byte
	Data []byte
}

// Bech32 defines the structure of an address native segwit
type Bech32 struct {
	Prefix string
	Data []byte 
}

// Blech32 defines the structure of a confidential address native segwit
type Blech32 struct {
	Version byte
	PublicKey []byte
	Data []byte 
}

// FromBase58 decodes a string that was base58 encoded and verifies the checksum.
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

// ToBase58 prepends a version byte and appends a four byte checksum.
func ToBase58(b *Base58) string {
	encoded := base58.CheckEncode(b.Data, b.Version)
	return encoded
}


// FromBech32 decodes a bech32 encoded string, returning the human-readable
// part and the data part excluding the checksum.
func FromBech32(address string) (*Bech32, error) {
	hrp, decoded, err := bech32.Decode(address)
	if err != nil {
		return nil, errors.New("Invalid address")
	}

	return &Bech32{hrp, decoded}, nil
}

// ToBech32 encodes a byte slice into a bech32 string with the
// human-readable part hrb. Note that the bytes must each encode 5 bits
func ToBech32(bc *Bech32) (string, error) {
	conv, err := bech32.ConvertBits(bc.Data, 8, 5, true)
	if err != nil {
		return "", errors.New("Invalid bech32 conversion")
	}
	encoded, err := bech32.Encode(bc.Prefix, conv)
	if err != nil {
		return "", errors.New("Invalid bech32 encoding")
	}
	return encoded, nil
}