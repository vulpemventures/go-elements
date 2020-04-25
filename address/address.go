package address

import (
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/bech32"
	"strings"
)

// Address defines the address as string
type Address struct {
	address string
}

// Base58 type defines the structure of an address legacy or wrapped segwit
type Base58 struct {
	Version byte
	Data    []byte
}

// Bech32 defines the structure of an address native segwit
type Bech32 struct {
	Prefix  string
	Version byte
	Data    []byte
}

// Blech32 defines the structure of a confidential address native segwit
type Blech32 struct {
	Version   byte
	PublicKey []byte
	Data      []byte
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

	return &Base58{version, decoded}, nil
}

// ToBase58 prepends a version byte and appends a four byte checksum.
func ToBase58(b *Base58) string {
	encoded := base58.CheckEncode(b.Data, b.Version)
	return encoded
}

// FromBech32 decodes a bech32 encoded string, returning the human-readable
// part and the data part excluding the checksum.
func FromBech32(address string) (*Bech32, error) {
	// Bech32 encoded segwit addresses start with a human-readable part
	// (hrp) followed by '1'. For Liquid mainnet the hrp is "ex", and for
	// testnet it is "ert".
	oneIndex := strings.LastIndexByte(address, '1')
	if oneIndex <= 1 {
		return nil, errors.New("Invalid Sewgit address")
	}
	hrp := address[:oneIndex+1]
	// The HRP is everything before the found '1'.
	prefix := hrp[:len(hrp)-1]
	// Decode the bech32 encoded address.
	_, data, err := bech32.Decode(address)
	if err != nil {
		return nil, err
	}

	// The first byte of the decoded address is the witness version, it must
	// exist.
	if len(data) < 1 {
		return nil, errors.New("no witness version")
	}

	// ...and be <= 16.
	version := data[0]
	if version > 16 {
		return nil, errors.New("invalid witness version")
	}

	// The remaining characters of the address returned are grouped into
	// words of 5 bits. In order to restore the original witness program
	// bytes, we'll need to regroup into 8 bit words.
	regrouped, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, err
	}

	// The regrouped data must be between 2 and 40 bytes.
	if len(regrouped) < 2 || len(regrouped) > 40 {
		return nil, errors.New("invalid data length")
	}

	// For witness version 0, address MUST be exactly 20 or 32 bytes.
	if version == 0 && len(regrouped) != 20 && len(regrouped) != 32 {
		return nil, errors.New("invalid data length for witness ")
	}

	return &Bech32{prefix, version, regrouped}, nil
}

// ToBech32 encodes a byte slice into a bech32 string with the
// human-readable part hrb. Note that the bytes must each encode 5 bits
func ToBech32(bc *Bech32) (string, error) {
	// Group the address bytes into 5 bit groups, as this is what is used to
	// encode each character in the address string.
	converted, err := bech32.ConvertBits(bc.Data, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Concatenate the witness version and program, and encode the resulting
	// bytes using bech32 encoding.
	combined := make([]byte, len(converted)+1)
	combined[0] = bc.Version
	copy(combined[1:], converted)
	bech, err := bech32.Encode(bc.Prefix, combined)
	if err != nil {
		return "", err
	}

	return bech, nil
}
