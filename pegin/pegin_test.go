package pegin

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vulpemventures/go-elements/block"
	"github.com/vulpemventures/go-elements/elementsutil"

	"github.com/btcsuite/btcd/wire"

	"github.com/stretchr/testify/assert"
)

func TestStripWitnessFromBtcTx(t *testing.T) {
	txHex := "020000000001019b7aefabe954160747e2f3ebe27940788abb427ee7dde2c857bf95f7ce8ff2990000000017160014ca4b5c9294aa8b827a639d2610d5747d906488d8feffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c40268710161a1e0100000017a914a8fcb1a6a1922012bae14c54caf510326dfa47f98702473044022049500e2cc5b09ec944d9a362bf1789dce07ce81e31a1cb0831a2b3906d53fff902201037a734559bfbfeeff44bbffa66dd14de6c0631eb702a3d29a1349db52010250121038a91c84aaeb1a41fdda631cf02b19fab2329c4ba3a9fe435339b380d80c5374a66000000"
	expected := "02000000019b7aefabe954160747e2f3ebe27940788abb427ee7dde2c857bf95f7ce8ff2990000000017160014ca4b5c9294aa8b827a639d2610d5747d906488d8feffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c40268710161a1e0100000017a914a8fcb1a6a1922012bae14c54caf510326dfa47f98766000000"

	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatal(err)
	}

	stripedTx, err := stripWitnessFromBtcTx(txBytes)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, hex.EncodeToString(stripedTx))
}

func TestSerializeValue(t *testing.T) {
	var value int64 = 1000000000
	expected := "00ca9a3b00000000"

	serializedValue, err := serializeValue(value)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, hex.EncodeToString(serializedValue))
}

func TestSerializeTxOutProof(t *testing.T) {
	txHex := "02000000000101f98f9665468889b67336bdeda87aa7556b465dca2615b42b225f56cd5c2b054c01000000171600140626f9faded4f428f44e87a13ccad4ca464e07b6feffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c402687182824180100000017a91491c518a33a7061958d1f33b1965ff1dc70abb45f87024730440220121bd7cf7700a670f53023c83e50548d52ceb3df4b4636e3ea6d3ba34137424a02200d6614a949c9cd7bb02fae505b4626b73e3c06901398ae4fcc422d2bd9e89df601210367ffea4c8a61f790a8456a170a744e2f588622a3b0ecc28633e70370bfc9baec00000000"
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatal(err)
	}

	var tx wire.MsgTx
	err = tx.BtcDecode(
		bytes.NewReader(txBytes),
		wire.ProtocolVersion,
		wire.LatestEncoding,
	)
	if err != nil {
		t.Fatal(err)
	}
	txHash := tx.TxHash().String()
	t.Log(txHash)

	txOutProof := "00000020fa203873242b50221d533889f7b7906a3946b505b8376e2d751e700010367d5849dfb02557386193ebf0f92a606958cbf249662dddecc55bd9f68d20aec0a226308f9e60ffff7f20000000000200000002d45deb54cebe4d401c5b3504a2c0f1114f29ddd959125c222034cf24484507229daedfd4722343ffb707185e16e9b0479dba6ed147b82c720efc96c3179b5db40105"

	merkleBlock, err := block.NewMerkleBlockFromHex(txOutProof)
	if err != nil {
		t.Fatal(err)
	}

	exists := false
	for _, v := range merkleBlock.PartialMerkleTree.TxHashes {
		t.Log(hex.EncodeToString(elementsutil.ReverseBytes(v)))
		if hex.EncodeToString(elementsutil.ReverseBytes(v)) == txHash {
			exists = true
		}
	}

	assert.Equal(t, true, exists)
}
