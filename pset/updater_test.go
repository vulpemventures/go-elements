package pset

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/transaction"
)

func TestUpdater(t *testing.T) {
	file, err := ioutil.ReadFile("data/updater.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []map[string]interface{}
	err = json.Unmarshal(file, &tests)

	for _, v := range tests {
		p, err := NewPsetFromBase64(v["base64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		updater, err := NewUpdater(p)

		for inIndex, vIn := range v["inputs"].([]interface{}) {
			in := vIn.(map[string]interface{})
			if in["nonWitnessUtxo"] != nil {
				tx, err := transaction.NewTxFromHex(in["nonWitnessUtxo"].(string))
				if err != nil {
					t.Fatal(err)
				}
				updater.AddInNonWitnessUtxo(tx, inIndex)
			} else {
				wu := in["witnessUtxo"].(map[string]interface{})
				asset, _ := hex.DecodeString(wu["asset"].(string))
				asset = append([]byte{0x01}, bufferutil.ReverseBytes(asset)...)
				script, _ := hex.DecodeString(wu["script"].(string))
				value, _ := confidential.SatoshiToElementsValue(uint64(wu["value"].(float64)))
				utxo := transaction.NewTxOutput(asset, value[:], script)
				updater.AddInWitnessUtxo(utxo, inIndex)
				redeemScript, _ := hex.DecodeString(in["redeemScript"].(string))
				updater.AddInRedeemScript(redeemScript, inIndex)
			}
			updater.AddInSighashType(txscript.SigHashType(int(in["sighashType"].(float64))), inIndex)
		}

		for outIndex, vOut := range v["outputs"].([]interface{}) {
			out := vOut.(map[string]interface{})
			redeemScript, _ := hex.DecodeString(out["redeemScript"].(string))
			updater.AddOutRedeemScript(redeemScript, outIndex)
		}

		base64Res, err := updater.Data.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		hexRes, err := updater.Data.ToHex()
		if err != nil {
			t.Fatal(err)
		}
		expectedBase64 := v["expectedBase64"].(string)
		expectedHex := v["expectedHex"].(string)
		if base64Res != expectedBase64 {
			t.Fatalf("Got: %s, expected: %s", base64Res, expectedBase64)
		}
		if hexRes != expectedHex {
			t.Fatalf("Got: %s, expected: %s", hexRes, expectedHex)
		}
	}
}

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

	assert.Equal(t, 0, len(updater.Data.UnsignedTx.Inputs))
	assert.Equal(t, 0, len(updater.Data.Inputs))

	updater.AddInput(&txInput)

	assert.Equal(t, 1, len(updater.Data.UnsignedTx.Inputs))
	assert.Equal(t, 1, len(updater.Data.Inputs))
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

	assert.Equal(t, 0, len(updater.Data.UnsignedTx.Outputs))
	assert.Equal(t, 0, len(updater.Data.Outputs))

	updater.AddOutput(&txOutput)

	assert.Equal(t, 1, len(updater.Data.UnsignedTx.Outputs))
	assert.Equal(t, 1, len(updater.Data.Outputs))
}
