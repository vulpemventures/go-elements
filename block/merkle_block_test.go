package block

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulpemventures/go-elements/elementsutil"
)

func TestDeserializeMerkleBlock(t *testing.T) {
	txOutProof := "0000003095a03ddcb18a359a1d41072ed373d45e57200f57d6f318238a7a6eb18df4c02dd4187f08f314f8436ac76f38cbe03a791a0893f26444ea5d5ec8f5b9b95a93015280ab60ffff7f20010000000200000002bdde18f707d02aa18ba82926965dc8bb8991d9510cd98e2812cc44b7aae8d3959745d887c8459cd4441f1dfe1a2d7ecbe225db87eeaa68bb22df6fdbf7017c480105"

	merkleBlock, err := NewMerkleBlockFromHex(txOutProof)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range merkleBlock.PartialMerkleTree.TxHashes {
		t.Log(hex.EncodeToString(elementsutil.ReverseBytes(v)))
	}
}

func TestExtractMatches(t *testing.T) {
	txOutProof := "0000003095a03ddcb18a359a1d41072ed373d45e57200f57d6f318238a7a6eb18df4c02dd4187f08f314f8436ac76f38cbe03a791a0893f26444ea5d5ec8f5b9b95a93015280ab60ffff7f20010000000200000002bdde18f707d02aa18ba82926965dc8bb8991d9510cd98e2812cc44b7aae8d3959745d887c8459cd4441f1dfe1a2d7ecbe225db87eeaa68bb22df6fdbf7017c480105"

	merkleBlock, err := NewMerkleBlockFromHex(txOutProof)
	if err != nil {
		t.Fatal(err)
	}

	hashMerkleRoot, matchedHashes, err := merkleBlock.ExtractMatches()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(
		t,
		true,
		merkleBlock.BlockHeader.MerkleRoot.IsEqual(hashMerkleRoot),
	)
	assert.Equal(t, 1, len(matchedHashes))
}
