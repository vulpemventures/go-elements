package pset

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/transaction"
	"testing"
)

func TestUpdaterAddInput(t *testing.T) {
	inputs := make([]*transaction.TxInput, 0)
	outputs := make([]*transaction.TxOutput, 0)
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}

	txInput := transaction.TxInput{
		Hash:  hash,
		Index: 2,
	}

	assert.Equal(t, 0, len(updater.Upsbt.UnsignedTx.Inputs))
	assert.Equal(t, 0, len(updater.Upsbt.Inputs))

	updater.AddInput(&txInput)

	assert.Equal(t, 1, len(updater.Upsbt.UnsignedTx.Inputs))
	assert.Equal(t, 1, len(updater.Upsbt.Inputs))
}

func TestUpdaterAddOutput(t *testing.T) {
	inputs := make([]*transaction.TxInput, 0)
	outputs := make([]*transaction.TxOutput, 0)
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	script, err := hex.DecodeString(
		"76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	if err != nil {
		t.Fatal(err)
	}

	asset, err := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
	if err != nil {
		t.Fatal(err)
	}

	txOutput := transaction.TxOutput{
		Asset:  asset,
		Value:  []byte{byte(42)},
		Script: script,
	}

	assert.Equal(t, 0, len(updater.Upsbt.UnsignedTx.Outputs))
	assert.Equal(t, 0, len(updater.Upsbt.Outputs))

	updater.AddOutput(&txOutput)

	assert.Equal(t, 1, len(updater.Upsbt.UnsignedTx.Outputs))
	assert.Equal(t, 1, len(updater.Upsbt.Outputs))
}

func TestCreateAddIssuanceSignAndBroadcast(t *testing.T) {
	// Generate sender random key pair.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash, _ := hex.DecodeString(utxos[0]["txid"].(string))
	txInputHash = bufferutil.ReverseBytes(txInputHash)
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	lbtc, _ := hex.DecodeString("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3" +
		"cf33c0419ca290e0751b225")
	lbtc = append([]byte{0x01}, bufferutil.ReverseBytes(lbtc)...)

	changeScript := p2wpkh.Script
	changeValue, _ := confidential.SatoshiToElementsValue(99999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], changeScript)

	feeScript := []byte{}
	feeValue, _ := confidential.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	arg := AddIssuanceArg{
		Precision: 0,
		Contract: &transaction.IssuanceContract{
			Name:      "Test",
			Ticker:    "TST",
			Version:   0,
			Precision: 0,
			Entity: transaction.IssuanceEntity{
				Domain: "test.io",
			},
		},
		AssetAmount:  1000,
		TokenAmount:  1,
		AssetAddress: address,
		TokenAddress: address,
		TokenFlag:    0,
		Net:          network.Regtest,
	}
	err = updater.AddIssuance(arg)
	if err != nil {
		t.Fatal(err)
	}

	err = updater.AddInSighashType(txscript.SigHashAll, 0)
	if err != nil {
		t.Fatal(err)
	}
	witValue, _ := confidential.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue[:], p2wpkh.Script)
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	if err != nil {
		t.Fatal(err)
	}
	legacyScript := append(append([]byte{0x76, 0xa9, 0x14}, p2wpkh.Hash...), []byte{0x88, 0xac}...)
	witHash := updater.Upsbt.UnsignedTx.HashForWitnessV0(0, legacyScript, witValue[:], txscript.SigHashAll)
	sig, err := privkey.Sign(witHash[:])
	if err != nil {
		t.Fatal(err)
	}

	sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))

	// Update the pset adding the input signature script and the pubkey.
	_, err = updater.Sign(0, sigWithHashType, pubkey.SerializeCompressed(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Finalize the partial transaction.
	p = updater.Upsbt
	err = FinalizeAll(p)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the final signed transaction from the Pset wrapper.
	finalTx, err := Extract(p)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize the transaction and try to broadcast.
	txHex, err := finalTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}
	txid, err := broadcast(txHex)
	if err != nil {
		t.Fatal(err)
	}

	if len(txid) <= 0 {
		t.Fatal("Expected transaction to be broadcasted")
	}
}
