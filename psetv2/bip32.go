package psetv2

import (
	"bytes"
	"encoding/binary"
)

//TODO add ref to btcutil

// DerivationPathWithPubKey encapsulates the data for the input and output
// DerivationPathWithPubKey key-value fields.
type DerivationPathWithPubKey struct {
	// PubKey is the raw pubkey serialized in compressed format.
	PubKey []byte

	// MasterKeyFingerprint is the finger print of the master pubkey.
	MasterKeyFingerprint uint32

	// Bip32Path is the BIP 32 path with child index as a distinct integer.
	Bip32Path []uint32
}

type TapDerivationPathWithPubKey struct {
	DerivationPathWithPubKey
	LeafHashes [][]byte
}

func (d *TapDerivationPathWithPubKey) sanityCheck() error {
	if len(d.LeafHashes) == 0 {
		return ErrInInvalidTapBip32Derivation
	}

	for _, leafHash := range d.LeafHashes {
		if len(leafHash) != 32 {
			return ErrInInvalidTapBip32Derivation
		}
	}

	return nil
}

// Bip32Sorter implements sort.Interface for the DerivationPathWithPubKey struct.
type Bip32Sorter []*DerivationPathWithPubKey

func (s Bip32Sorter) Len() int { return len(s) }

func (s Bip32Sorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s Bip32Sorter) Less(i, j int) bool {
	return bytes.Compare(s[i].PubKey, s[j].PubKey) < 0
}

// readBip32Derivation deserializes a byte slice containing chunks of 4 byte
// little endian encodings of uint32 values, the first of which is the
// masterkeyfingerprint and the remainder of which are the derivation path.
func readBip32Derivation(path []byte) (uint32, []uint32, error) {
	if len(path)%4 != 0 || len(path)/4-1 < 1 {
		return 0, nil, ErrInvalidPsbtFormat
	}

	masterKeyInt := binary.LittleEndian.Uint32(path[:4])

	var paths []uint32
	for i := 4; i < len(path); i += 4 {
		paths = append(paths, binary.LittleEndian.Uint32(path[i:i+4]))
	}

	return masterKeyInt, paths, nil
}

// SerializeBIP32Derivation takes a master key fingerprint as defined in BIP32,
// along with a path specified as a list of uint32 values, and returns a
// bytestring specifying the derivation in the format required by BIP174: //
// master key fingerprint (4) || child index (4) || child index (4) || ....
func SerializeBIP32Derivation(masterKeyFingerprint uint32,
	bip32Path []uint32) []byte {

	var masterKeyBytes [4]byte
	binary.LittleEndian.PutUint32(masterKeyBytes[:], masterKeyFingerprint)

	derivationPath := make([]byte, 0, 4+4*len(bip32Path))
	derivationPath = append(derivationPath, masterKeyBytes[:]...)
	for _, path := range bip32Path {
		var pathbytes [4]byte
		binary.LittleEndian.PutUint32(pathbytes[:], path)
		derivationPath = append(derivationPath, pathbytes[:]...)
	}

	return derivationPath
}
