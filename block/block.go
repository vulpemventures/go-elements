package block

import (
	"bytes"
	"encoding/hex"

	"github.com/vulpemventures/go-elements/transaction"
)

const (
	null = iota
	compact
	full

	hashSize     = 32
	blockVersion = 536870912
)

type Block struct {
	Header       *Header
	Transactions []*transaction.Transaction
}

func NewFromBuffer(buf *bytes.Buffer) (*Block, error) {
	return deserialize(buf)
}

func NewFromHex(h string) (*Block, error) {
	hexBytes, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(hexBytes)
	return NewFromBuffer(buf)
}

type Header struct {
	// Version - should be 0x20000000 except when versionbits signalling
	version uint32
	// Previous blockhash
	prevBlockHash []byte
	// Transaction Merkle root
	merkleRoot []byte
	// Block timestamp
	time uint32
	// Block height
	height uint32
	// Block signature and dynamic federation-related data
	ext *ExtData
}

// ExtData block signature and dynamic federation-related data
type ExtData struct {
	// Liquid v1-style static `signblockscript` and witness
	proof *Proof
	// Dynamic federations
	dynamicFederation *DynamicFederation
}

// Proof Liquid v1-style static `signblockscript` and witness
type Proof struct {
	// Block "public key"
	challenge []byte
	// Satisfying witness to the above challenge, or nothing
	solution []byte
}

type DynamicFederation struct {
	current          *DynamicFederationParams
	proposed         *DynamicFederationParams
	signBlockWitness [][]byte
}

type DynamicFederationParams struct {
	compactParams *CompactParams
	fullParams    *FullParams
}

// CompactParams params where the fedpeg data and extension space
// are not included, and are assumed to be equal to the values
// from the previous block
type CompactParams struct {
	// "scriptPubKey" used for block signing
	signBlockScript []byte
	/// Maximum, in bytes, of the size of a blocksigning witness
	signBlockWitnessLimit uint32
	/// Merkle root of extra data
	elidedRoot []byte
}

// FullParams full dynamic federations parameters
type FullParams struct {
	// "scriptPubKey" used for block signing
	signBlockScript []byte
	// Maximum, in bytes, of the size of a blocksigning witness
	signBlockWitnessLimit uint32
	// Untweaked `scriptPubKey` used for pegins
	fedpegProgram []byte
	// For v0 fedpeg programs, the witness script of the untweaked
	// pegin address. For future versions, this data has no defined
	// meaning and will be considered "anyone can spend".
	fedpegScript []byte
	/// "Extension space" used by Liquid for PAK key entries
	extensionSpace [][]byte
}
