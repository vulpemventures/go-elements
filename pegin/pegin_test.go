package pegin

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vulpemventures/go-elements/block"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/transaction"

	"github.com/btcsuite/btcd/chaincfg"
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

	stripedTx, err := StripWitnessFromBtcTx(txBytes)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, hex.EncodeToString(stripedTx))
}

func TestSerializeValue(t *testing.T) {
	var value int64 = 1000000000
	expected := "00ca9a3b00000000"

	serializedValue, err := SerializeValue(value)
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
		if hex.EncodeToString(elementsutil.ReverseBytes(v)) == txHash {
			exists = true
		}
	}

	assert.Equal(t, true, exists)
}

func TestSerializePeginWitness(t *testing.T) {
	claimScript := "0014f66ddc42aa6626cc7ff78ef28e333ef9c37a0da3"
	btcTxHex := "020000000001017637eca164aaf48a5bf200b46457053ea41ed12efc58fb0039c674c6c3c526700000000017160014f410f2ef1b4a9437f690691898798823b466e3d1feffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c4026878053e90b0000000017a914d28abf72575acf237f29fa17f7ec2ac4eff56d77870247304402207715a047ae2fd9c8f9b1dd9efafc97dcaf7af5c2fec95b735dab4c73a1004934022037b5ba40c7c27497ad73e915f0f12c4bb2443d21839e1ce7879d15b85231ffd901210231881188f837f134f4afea25ce26c36b6bf01bcf1b76862751b95ea5d781278594000000"
	btcTxOutProof := "00000030b60a7067a3b57066cb0b1a17b4f4e2883c3352b3ffb74ef92b833df29818d535c8c1d8494c95182deea29dd2d02738f043e5ae6178a3a3f4478d1c85302dd3e7cfa0c060ffff7f20000000000200000002e6e5209a17f2ad4482a618a58cc9d7d772a53de242867066c786868289d234663177663c3649d6a5dc057bbbb2f33c176d6b52223b180084a0d73618e44259cf0105"

	peggedAssetBytes, err := hex.DecodeString(network.Regtest.AssetID)
	if err != nil {
		t.Fatal(err)
	}

	parentBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	parentBlockHashBytes, err := hex.DecodeString(parentBlockHash)
	if err != nil {
		t.Fatal(err)
	}

	fedpegScriptBytes, err := hex.DecodeString("51")
	if err != nil {
		t.Fatal(err)
	}

	btcTxBytes, err := hex.DecodeString(btcTxHex)
	if err != nil {
		t.Fatal(err)
	}

	btcTxOutProofBytes, err := hex.DecodeString(btcTxOutProof)
	if err != nil {
		t.Fatal(err)
	}

	claimScriptBytes, err := hex.DecodeString(claimScript)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := Claim(
		&chaincfg.RegressionNetParams,
		false,
		append([]byte{0x01}, elementsutil.ReverseBytes(peggedAssetBytes)...),
		parentBlockHashBytes,
		fedpegScriptBytes,
		fedpegScriptBytes, // contract = fedpegscript here
		btcTxBytes,
		btcTxOutProofBytes,
		claimScriptBytes,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	peginWitness := tx.Inputs[0].PeginWitness
	assert.NotNil(t, peginWitness)

	txHex, err := tx.ToHex()
	if err != nil {
		t.Fatal(err)
	}

	transactionAfterToHex, err := transaction.NewTxFromHex(txHex)
	if err != nil {
		t.Fatal(err)
	}

	peginWitnessAfterToHex := transactionAfterToHex.Inputs[0].PeginWitness
	assert.Equal(t, peginWitness, peginWitnessAfterToHex)
}
