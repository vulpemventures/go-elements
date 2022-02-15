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

	hashSize = 32

	DYNAFED_HF_MASK = uint32(1 << 31)
)

type Block struct {
	Header           *Header
	TransactionsData *Transactions
}

type Transactions struct {
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
	Version uint32
	// Previous blockhash
	PrevBlockHash []byte
	// Transaction Merkle root
	MerkleRoot []byte
	// Block timestamp
	Timestamp uint32
	// Block Height
	Height uint32
	// Block signature and dynamic federation-related data
	ExtData *ExtData
}

// ExtData block signature and dynamic federation-related data
type ExtData struct {
	// Liquid v1-style static `signblockscript` and witness
	Proof *Proof
	// Dynamic federations
	DynamicFederation *DynamicFederation
	// is dynamic federation
	IsDyna bool
}

// Proof Liquid v1-style static `signblockscript` and witness
type Proof struct {
	// Block "public key"
	Challenge []byte
	// Satisfying witness to the above Challenge, or nothing
	Solution []byte
}

type DynamicFederation struct {
	Current          *DynamicFederationParams
	Proposed         *DynamicFederationParams
	SignBlockWitness [][]byte
}

type DynamicFederationParams struct {
	CompactParams *CompactParams
	FullParams    *FullParams
}

// CompactParams params where the fedpeg data and extension space
// are not included, and are assumed to be equal to the values
// from the previous block
type CompactParams struct {
	// "scriptPubKey" used for block signing
	SignBlockScript []byte
	/// Maximum, in bytes, of the size of a blocksigning witness
	SignBlockWitnessLimit uint32
	/// Merkle root of extra data
	ElidedRoot []byte
}

// FullParams full dynamic federations parameters
type FullParams struct {
	// "scriptPubKey" used for block signing
	SignBlockScript []byte
	// Maximum, in bytes, of the size of a blocksigning witness
	SignBlockWitnessLimit uint32
	// Untweaked `scriptPubKey` used for pegins
	FedpegProgram []byte
	// For v0 fedpeg programs, the witness script of the untweaked
	// pegin address. For future versions, this data has no defined
	// meaning and will be considered "anyone can spend".
	FedpegScript []byte
	/// "Extension space" used by Liquid for PAK key entries
	ExtensionSpace [][]byte
}
