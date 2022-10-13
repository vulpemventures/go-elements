package address

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/blech32"
	"github.com/vulpemventures/go-elements/network"
)

const (
	P2Pkh = iota
	P2Sh
	ConfidentialP2Pkh
	ConfidentialP2Sh
	P2Wpkh
	P2Wsh
	ConfidentialP2Wpkh
	ConfidentialP2Wsh
	P2TR
	ConfidentialP2TR
)

const (
	P2PkhScript = iota + 1
	P2ShScript
	P2MultiSigScript
	P2WpkhScript
	P2WshScript
	P2TRScript

	ripemd160Size = 20
)

// Base58 type defines the structure of a legacy or wrapped segwit address
type Base58 struct {
	Version byte
	Data    []byte
}

// Base58Confidential type defines the structure of a legacy or wrapped segwit
// confidential address
type Base58Confidential struct {
	Base58
	Version   byte
	PublicKey []byte
}

// Bech32 defines the structure of an address native segwit
type Bech32 struct {
	Prefix  string
	Version byte
	Program []byte
}

// Blech32 defines the structure of a confidential address native segwit
type Blech32 struct {
	Prefix    string
	Version   byte
	PublicKey []byte
	Program   []byte
}

// AddressInfo holds info about a receiving address.
type AddressInfo struct {
	Address     string
	Script      []byte
	BlindingKey []byte
}

// FromBase58 decodes a string that was base58 encoded and verifies the checksum.
func FromBase58(address string) (*Base58, error) {
	decoded, version, err := base58.CheckDecode(address)
	if err != nil {
		return nil, errors.New("invalid address")
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
// part and the Data part excluding the checksum.
func FromBech32(address string) (*Bech32, error) {
	// Bech32 encoded segwit addresses start with a human-readable part
	// (hrp) followed by '1'. For Liquid mainnet the hrp is "ex", and for
	// testnet it is "ert".
	oneIndex := strings.LastIndexByte(address, '1')
	if oneIndex <= 1 {
		return nil, errors.New("invalid Sewgit address")
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

	// The regrouped Data must be between 2 and 40 bytes.
	if len(regrouped) < 2 || len(regrouped) > 40 {
		return nil, errors.New("invalid Data Length")
	}

	// For witness version 0, address MUST be exactly 20 or 32 bytes.
	if version == 0 && len(regrouped) != 20 && len(regrouped) != 32 {
		return nil, errors.New("invalid Data Length for witness ")
	}

	return &Bech32{prefix, version, regrouped}, nil
}

// ToBech32 encodes a byte slice into a bech32 string with the
// human-readable part hrb. Note that the bytes must each encode 5 bits
func ToBech32(bc *Bech32) (string, error) {
	// Group the address bytes into 5 bit groups, as this is what is used to
	// encode each character in the address string.
	converted, err := bech32.ConvertBits(bc.Program, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Concatenate the witness version and program, and encode the resulting
	// bytes using bech32 encoding.
	combined := make([]byte, len(converted)+1)
	combined[0] = bc.Version
	copy(combined[1:], converted)

	var bech string

	switch bc.Version {
	case 0:
		bech, err = bech32.Encode(bc.Prefix, combined)
		if err != nil {
			return "", err
		}
	case 1:
		bech, err = bech32.EncodeM(bc.Prefix, combined)
		if err != nil {
			return "", err
		}
	default:
		return "", errors.New("unsupported witness version")
	}

	return bech, nil
}

// FromBase58Confidential decodes a confidenail address that was base58 encoded
//  and verifies the checksum.
func FromBase58Confidential(address string) (*Base58Confidential, error) {
	decoded, version, err := base58.CheckDecode(address)
	if err != nil {
		return nil, errors.New("invalid address")
	}

	if len(decoded) < 54 {
		return nil, errors.New(address + " is too short")
	}
	if len(decoded) > 54 {
		return nil, errors.New(address + " is too long")
	}

	// Blinded decoded address has the form:
	// BLIND_PREFIX | ADDRESS_PREFIX | BLINDING_KEY | SCRIPT_HASH
	// Prefixes are 1 byte long, thus blinding key always starts at 3rd byte

	return &Base58Confidential{
		Base58{
			decoded[0],
			decoded[34:],
		},
		version,
		decoded[1:34],
	}, nil
}

// ToBase58Confidential prepends a version byte and appends a four byte checksum.
func ToBase58Confidential(b *Base58Confidential) string {
	data := append([]byte{b.Base58.Version}, b.PublicKey...)
	data = append(data, b.Base58.Data...)
	encoded := base58.CheckEncode(data, b.Version)
	return encoded
}

// FromBlech32 decodes a blech32 encoded string, returning the human-readable
// part and the Data part excluding the checksum.
func FromBlech32(address string) (*Blech32, error) {
	// Blech32 encoded segwit addresses start with a human-readable part
	// (hrp) followed by '1'. For Liquid mainnet the hrp is "ex", and for
	// testnet it is "ert".
	oneIndex := strings.LastIndexByte(address, '1')
	if oneIndex <= 1 {
		return nil, errors.New("invalid Sewgit address")
	}
	hrp := address[:oneIndex+1]
	// The HRP is everything before the found '1'.
	prefix := hrp[:len(hrp)-1]

	// Decode the bech32 encoded address.
	_, data, err := blech32.Decode(address)
	if err != nil {
		return nil, err
	}

	// The first byte of the decoded address is the witness version, it must
	// exist.
	if len(data) < 1 {
		return nil, fmt.Errorf("no witness version")
	}

	// ...and be <= 16.
	version := data[0]
	if version > 16 {
		return nil, fmt.Errorf("invalid witness version: %v", version)
	}

	// The remaining characters of the address returned are grouped into
	// words of 5 bits. In order to restore the original witness program
	// bytes, we'll need to regroup into 8 bit words.
	regrouped, err := blech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, err
	}

	if len(regrouped) < 2 || len(regrouped) > 40+33 {
		return nil, fmt.Errorf("invalid Data Length")
	}

	// For witness version 0, address MUST be exactly 20+33 or 32+33 bytes.
	if version == 0 && len(regrouped) != 20+33 && len(regrouped) != 32+33 {
		return nil, fmt.Errorf("invalid Data Length for witness "+
			"version 0: %v", len(regrouped))
	}

	return &Blech32{
		prefix,
		version,
		regrouped[:33],
		regrouped[33:],
	}, nil
}

// ToBlech32 encodes a byte slice into a blech32 string
func ToBlech32(bl *Blech32) (string, error) {
	// Group the address bytes into 5 bit groups, as this is what is used to
	// encode each character in the address string.
	converted, err := blech32.ConvertBits(
		append(bl.PublicKey, bl.Program...),
		8,
		5,
		true,
	)
	if err != nil {
		return "", err
	}

	// Concatenate the witness version and program, and encode the resulting
	// bytes using blech32 encoding.
	combined := make([]byte, len(converted)+1)
	combined[0] = bl.Version
	copy(combined[1:], converted)
	enc, err := blech32.EncodingTypeFromSegwitVersion(bl.Version)
	if err != nil {
		return "", err
	}

	blech32Addr, err := blech32.Encode(bl.Prefix, combined, enc)
	if err != nil {
		return "", err
	}

	// Check validity by decoding the created address.
	blech, err := FromBlech32(blech32Addr)
	if err != nil {
		return "", fmt.Errorf("invalid blech32 address: %v", err)
	}

	blechData := append(blech.PublicKey, blech.Program...)
	blData := append(bl.PublicKey, bl.Program...)

	if blech.Version != bl.Version || !bytes.Equal(blechData, blData) {
		return "", fmt.Errorf("invalid segwit address")
	}

	return blech32Addr, nil
}

// FromConfidential returns the unconfidential address and the blinding public
// key that form the confidential address
func FromConfidential(address string) (*AddressInfo, error) {
	net, err := NetworkForAddress(address)
	if err != nil {
		return nil, err
	}

	addressType, err := DecodeType(address)
	if err != nil {
		return nil, err
	}

	var addr string
	var blindingKey []byte
	switch addressType {
	case ConfidentialP2Pkh, ConfidentialP2Sh:
		fromBase58, err := FromBase58Confidential(address)
		if err != nil {
			return nil, err
		}

		addr = ToBase58(&fromBase58.Base58)
		blindingKey = fromBase58.PublicKey
	case ConfidentialP2Wpkh, ConfidentialP2Wsh, ConfidentialP2TR:
		fromBlech32, err := FromBlech32(address)
		if err != nil {
			return nil, err
		}

		addr, err = ToBech32(&Bech32{
			Prefix:  net.Bech32,
			Version: fromBlech32.Version,
			Program: fromBlech32.Program,
		})
		if err != nil {
			return nil, err
		}
		blindingKey = fromBlech32.PublicKey
	default:
		return nil, errors.New("unknown address type")
	}

	script, _ := ToOutputScript(addr)
	return &AddressInfo{
		BlindingKey: blindingKey,
		Address:     addr,
		Script:      script,
	}, nil
}

// ToConfidential returns the confidential address formed by the given
// unconfidential address and blinding public key
func ToConfidential(ca *AddressInfo) (string, error) {
	net, err := NetworkForAddress(ca.Address)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(ca.Address, net.Bech32) {
		b32, _ := FromBech32(ca.Address)
		return ToBlech32(&Blech32{
			Prefix:    net.Blech32,
			Version:   b32.Version,
			Program:   b32.Program,
			PublicKey: ca.BlindingKey,
		})
	}

	b58, _ := FromBase58(ca.Address)
	return ToBase58Confidential(&Base58Confidential{
		*b58,
		net.Confidential,
		ca.BlindingKey,
	}), nil
}

// NetworkForAddress returns the network based on the prefix of the given address
func NetworkForAddress(address string) (*network.Network, error) {
	if strings.HasPrefix(address, network.Liquid.Bech32) ||
		strings.HasPrefix(address, network.Liquid.Blech32) {
		return &network.Liquid, nil
	}

	if strings.HasPrefix(address, network.Regtest.Bech32) ||
		strings.HasPrefix(address, network.Regtest.Blech32) {
		return &network.Regtest, nil
	}

	if strings.HasPrefix(address, network.Testnet.Bech32) ||
		strings.HasPrefix(address, network.Testnet.Blech32) {
		return &network.Testnet, nil
	}

	_, prefix, err := base58.CheckDecode(address)
	if err != nil {
		return nil, err
	}

	if prefix == network.Liquid.Confidential ||
		prefix == network.Liquid.PubKeyHash ||
		prefix == network.Liquid.ScriptHash {
		return &network.Liquid, nil
	}

	if prefix == network.Regtest.Confidential ||
		prefix == network.Regtest.PubKeyHash ||
		prefix == network.Regtest.ScriptHash {
		return &network.Regtest, nil
	}

	if prefix == network.Testnet.Confidential ||
		prefix == network.Testnet.PubKeyHash ||
		prefix == network.Testnet.ScriptHash {
		return &network.Testnet, nil
	}

	return nil, errors.New("unknown prefix for address")
}

//ToOutputScript creates a new script to pay a transaction output to a the
//specified address
func ToOutputScript(address string) ([]byte, error) {
	addressType, err := DecodeType(address)
	if err != nil {
		return nil, err
	}

	switch addressType {
	case P2Pkh:
		pubKeyHash, _, err := base58.CheckDecode(address)
		if err != nil {
			return nil, err
		}
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_DUP).
			AddOp(txscript.OP_HASH160).
			AddData(pubKeyHash).
			AddOp(txscript.OP_EQUALVERIFY).
			AddOp(txscript.OP_CHECKSIG).
			Script()

	case P2Sh:
		scriptHash, _, err := base58.CheckDecode(address)
		if err != nil {
			return nil, err
		}
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_HASH160).
			AddData(scriptHash).
			AddOp(txscript.OP_EQUAL).
			Script()

	case ConfidentialP2Pkh:
		decoded, _, err := base58.CheckDecode(address)
		if err != nil {
			return nil, err
		}
		prefixPlusBlindKeySize := 34
		pubKeyHash := decoded[prefixPlusBlindKeySize:]
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_DUP).
			AddOp(txscript.OP_HASH160).
			AddData(pubKeyHash).
			AddOp(txscript.OP_EQUALVERIFY).
			AddOp(txscript.OP_CHECKSIG).
			Script()
	case ConfidentialP2Sh:
		decoded, _, err := base58.CheckDecode(address)
		if err != nil {
			return nil, err
		}
		prefixPlusBlindKeySize := 34
		scriptHash := decoded[prefixPlusBlindKeySize:]
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_HASH160).
			AddData(scriptHash).
			AddOp(txscript.OP_EQUAL).
			Script()
	case P2Wpkh, P2Wsh, P2TR:
		fromBech32, err := FromBech32(address)
		if err != nil {
			return nil, err
		}

		versionOpcode := byte(txscript.OP_0)
		if fromBech32.Version == 1 {
			versionOpcode = txscript.OP_1
		}

		return txscript.NewScriptBuilder().
			AddOp(versionOpcode).
			AddData(fromBech32.Program).
			Script()
	case ConfidentialP2Wpkh, ConfidentialP2Wsh, ConfidentialP2TR:
		fromBlech32, err := FromBlech32(address)
		if err != nil {
			return nil, err
		}

		versionOpcode := byte(txscript.OP_0)
		if fromBlech32.Version == 1 {
			versionOpcode = txscript.OP_1
		}

		return txscript.NewScriptBuilder().
			AddOp(versionOpcode).
			AddData(fromBlech32.Program).
			Script()
	default:
		return nil, errors.New("unsupported address type")
	}
}

// GetScriptType returns the type of the given script (p2pkh, p2sh, etc.)
func GetScriptType(script []byte) int {
	switch script[0] {
	case txscript.OP_0: // segwit v0
		if len(script[2:]) == 20 {
			return P2WpkhScript
		}
		return P2WshScript
	case txscript.OP_1: // segwit v1 (taproot)
		return P2TRScript
	case txscript.OP_HASH160:
		return P2ShScript
	case txscript.OP_DUP:
		return P2PkhScript
	default:
		return P2MultiSigScript
	}
}

//DecodeType returns address type
func DecodeType(address string) (int, error) {
	net, err := NetworkForAddress(address)
	if err != nil {
		return -1, err
	}

	if isBlech32(address, *net) {
		return decodeBlech32(address, *net)
	}
	if isBech32(address, *net) {
		return decodeBech32(address, *net)
	}
	return decodeBase58(address, *net)
}

// IsConfidential checks whether the given address is confidential
func IsConfidential(address string) (bool, error) {
	addressType, err := DecodeType(address)
	if err != nil {
		return false, err
	}

	isConfidential := (addressType == ConfidentialP2Pkh ||
		addressType == ConfidentialP2Sh ||
		addressType == ConfidentialP2Wpkh ||
		addressType == ConfidentialP2Wsh ||
		addressType == ConfidentialP2TR)

	return isConfidential, nil
}

func isBlech32(address string, net network.Network) bool {
	return strings.HasPrefix(address, net.Blech32)
}

func decodeBlech32(address string, net network.Network) (int, error) {
	fromBlech32, err := FromBlech32(address)
	if err != nil {
		return 0, err
	}

	if fromBlech32.Version == 0 {
		switch len(fromBlech32.Program) {
		case 20:
			return ConfidentialP2Wpkh, nil
		case 32:
			return ConfidentialP2Wsh, nil
		default:
			return 0, errors.New("invalid program Length")
		}
	}

	if fromBlech32.Version == 1 {
		return ConfidentialP2TR, nil
	}

	return 0, errors.New("invalid segwit version")
}

func isBech32(address string, net network.Network) bool {
	return strings.HasPrefix(address, net.Bech32)
}

func decodeBech32(address string, net network.Network) (int, error) {
	fromBech32, err := FromBech32(address)
	if err != nil {
		return 0, err
	}

	if fromBech32.Version == 0 {
		switch len(fromBech32.Program) {
		case 20:
			return P2Wpkh, nil
		case 32:
			return P2Wsh, nil
		default:
			return 0, errors.New("invalid program Length")
		}
	}

	if fromBech32.Version == 1 {
		return P2TR, nil
	}

	return 0, errors.New("invalid segwit version")
}

func decodeBase58(address string, net network.Network) (int, error) {
	decoded, netID, err := base58.CheckDecode(address)
	if err != nil {
		if err == base58.ErrChecksum {
			return 0, errors.New("checksum mismatch")
		}
		return 0, errors.New("decoded address is of unknown format")
	}

	if netID == net.Confidential {
		prefixPlusBlindKeySize := 34
		switch len(decoded[prefixPlusBlindKeySize:]) {
		case ripemd160Size:
			prefix := decoded[0]
			isP2PKH := prefix == net.PubKeyHash
			isP2SH := prefix == net.ScriptHash
			switch {
			case isP2PKH && isP2SH:
				return 0, errors.New("address collision")
			case isP2PKH:
				return ConfidentialP2Pkh, nil
			case isP2SH:
				return ConfidentialP2Sh, nil
			default:
				return 0, errors.New("unknown address type")
			}

		default:
			return 0, errors.New("decoded address is of unknown size")
		}
	}

	switch len(decoded) {
	case ripemd160Size:
		isP2PKH := netID == net.PubKeyHash
		isP2SH := netID == net.ScriptHash
		switch {
		case isP2PKH && isP2SH:
			return 0, errors.New("address collision")
		case isP2PKH:
			return P2Pkh, nil
		case isP2SH:
			return P2Sh, nil
		default:
			return 0, errors.New("unknown address type")
		}

	default:
		return 0, errors.New("decoded address is of unknown size")
	}
}
