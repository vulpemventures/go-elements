package block

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/wire"

	"github.com/btcsuite/btcd/blockchain"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	// The maximum allowed weight for a block, see BIP 141 (network rule)
	maxBlockWeight       = 4000000
	witnessScaleFactor   = 4
	minTransactionWeight = witnessScaleFactor * 60 // 60 is the lower bound for the size of a valid serialized tx

)

type MerkleBlock struct {
	BlockHeader       *wire.BlockHeader
	PartialMerkleTree *PartialMerkleTree
}

type PartialMerkleTree struct {
	TxTotalCount uint32
	TxHashes     [][]byte
	FBad         bool
	VBits        []bool
}

func NewMerkleBlockFromBuffer(buf *bytes.Buffer) (*MerkleBlock, error) {
	return deserializeMerkleBlock(buf)
}

func NewMerkleBlockFromHex(h string) (*MerkleBlock, error) {
	hexBytes, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(hexBytes)
	return NewMerkleBlockFromBuffer(buf)
}

func (m *MerkleBlock) ExtractMatches() (*chainhash.Hash, []chainhash.Hash, error) {
	vMatch := make([]chainhash.Hash, 0)

	if m.PartialMerkleTree.TxTotalCount == 0 {
		return nil, nil, errors.New("tx count equal 0")
	}

	if m.PartialMerkleTree.TxTotalCount > maxBlockWeight/minTransactionWeight {
		return nil, nil, errors.New("invalid tx count")
	}
	if len(m.PartialMerkleTree.TxHashes) > int(m.PartialMerkleTree.TxTotalCount) {
		return nil, nil, errors.New(
			"there can never be more hashes provided than one for every txid",
		)
	}

	if len(m.PartialMerkleTree.VBits) < len(m.PartialMerkleTree.TxHashes) {
		return nil, nil, errors.New(
			"there must be at least one bit per node in the partial tree, " +
				"and at least one node per hash",
		)
	}

	// Calculate the number of merkle branches (height) in the tree.
	height := uint32(0)
	for m.calcTreeWidth(height) > 1 {
		height++
	}

	var bitsUsed, hashUsed, position = 0, 0, 0
	hashMerkleRoot, err := m.traverseAndExtract(
		height,
		position,
		&bitsUsed,
		&hashUsed,
		&vMatch,
	)
	if err != nil {
		return nil, nil, err
	}

	if m.PartialMerkleTree.FBad {
		return nil, nil, errors.New(
			"there must be at least one bit per node in the partial tree, " +
				"and at least one node per hash",
		)
	}
	// verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
	if (bitsUsed+7)/8 != (len(m.PartialMerkleTree.VBits)+7)/8 {
		return nil, nil, errors.New(
			"except for the padding caused by serializing it as a byte" +
				" sequence, not all bits were consumed",
		)
	}
	// verify that all hashes were consumed
	if hashUsed != len(m.PartialMerkleTree.TxHashes) {
		return nil, nil, errors.New("not all hashes were consumed")
	}

	return hashMerkleRoot, vMatch, nil
}

func (m *MerkleBlock) traverseAndExtract(
	height uint32,
	position int,
	bitsUsed *int,
	hashUsed *int,
	vMatch *[]chainhash.Hash,
) (*chainhash.Hash, error) {
	if *bitsUsed >= len(m.PartialMerkleTree.VBits) {
		m.PartialMerkleTree.FBad = true
		return nil, errors.New("overflowed the bits array")
	}

	fParentOfMatch := m.PartialMerkleTree.VBits[*bitsUsed]
	*bitsUsed++
	if height == 0 || !fParentOfMatch {
		// if at height 0, or nothing interesting below, use stored hash and do not descend
		if *hashUsed >= len(m.PartialMerkleTree.TxHashes) {
			m.PartialMerkleTree.FBad = true
			return nil, errors.New("overflowed the hash array")
		}
		hash, err := chainhash.NewHash(m.PartialMerkleTree.TxHashes[*hashUsed])
		if err != nil {
			return nil, err
		}

		*hashUsed++
		if height == 0 && fParentOfMatch { // in case of height 0, we have a matched txid
			*vMatch = append(*vMatch, *hash)
		}

		return hash, nil
	} else {
		//otherwise, descend into the subtrees to extract matched txids and hashes
		left, err := m.traverseAndExtract(
			height-1,
			position*2,
			bitsUsed,
			hashUsed,
			vMatch,
		)
		if err != nil {
			return nil, err
		}
		var right *chainhash.Hash
		if position*2+1 < int(m.calcTreeWidth(height-1)) {
			right, err = m.traverseAndExtract(
				height-1,
				position*2+1,
				bitsUsed,
				hashUsed,
				vMatch,
			)
			if err != nil {
				return nil, err
			}
			if left.IsEqual(right) {
				// The left and right branches should never be identical, as the transaction
				// hashes covered by them must each be unique.
				m.PartialMerkleTree.FBad = true
			}
		} else {
			right = left
		}

		hash := blockchain.HashMerkleBranches(left, right)
		return &hash, nil
	}
}

// calcTreeWidth calculates and returns the the number of nodes (width) or a
// merkle tree at the given depth-first height.
func (m *MerkleBlock) calcTreeWidth(height uint32) uint32 {
	return (m.PartialMerkleTree.TxTotalCount + (1 << height) - 1) >> height
}

func deserializePartialMerkleTree(
	mb wire.MsgMerkleBlock,
) (*PartialMerkleTree, error) {
	txHashes := make([][]byte, 0, len(mb.Hashes))
	for _, v := range mb.Hashes {

		txHashes = append(txHashes, v.CloneBytes())
	}

	return &PartialMerkleTree{
		TxTotalCount: mb.Transactions,
		TxHashes:     txHashes,
		FBad:         false,
		VBits:        serializeVBits(mb.Flags),
	}, nil
}

func deserializeMerkleBlock(buf *bytes.Buffer) (*MerkleBlock, error) {
	mb := wire.MsgMerkleBlock{}
	err := mb.BtcDecode(buf, wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return nil, err
	}

	partialMerkleTree, err := deserializePartialMerkleTree(mb)
	if err != nil {
		return nil, err
	}

	return &MerkleBlock{
		BlockHeader:       &mb.Header,
		PartialMerkleTree: partialMerkleTree,
	}, nil
}

func serializeVBits(b []byte) []bool {
	bits := make([]bool, 0)

	for _, v := range b {
		l := byteToBits(v)
		for _, v := range l {
			if v == 1 {
				bits = append(bits, true)
			} else {
				bits = append(bits, false)
			}
		}
	}

	return bits
}

func byteToBits(b byte) []byte {
	return []byte{
		(b >> 0) & 0x1,
		(b >> 1) & 0x1,
		(b >> 2) & 0x1,
		(b >> 3) & 0x1,
		(b >> 4) & 0x1,
		(b >> 5) & 0x1,
		(b >> 6) & 0x1,
		(b >> 7) & 0x1,
	}
}
