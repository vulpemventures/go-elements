package pset

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
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
