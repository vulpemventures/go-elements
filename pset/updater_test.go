package pset

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/elementsutil"
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
				asset = append([]byte{0x01}, elementsutil.ReverseBytes(asset)...)
				script, _ := hex.DecodeString(wu["script"].(string))
				value, _ := elementsutil.SatoshiToElementsValue(uint64(wu["value"].(float64)))
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

func TestUpdaterAddIssuance(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			args            AddIssuanceArgs
			expectedAsset   string
			expectedToken   string
			expectedNumOuts int
		}{
			{
				args: AddIssuanceArgs{
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
					AssetAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
					TokenAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
				},
				expectedNumOuts: 2,
				expectedAsset:   "707953a405b1a79180ec7830e51d53997b3d1ff9aa614513266059dbfbbdbeb7",
				expectedToken:   "c99343e56d9783a816b866c48d182a9537d4979f1ed66d90ac6a49ec773daee9",
			},
			{
				args: AddIssuanceArgs{
					Precision:    0,
					AssetAmount:  1000,
					TokenAmount:  1,
					AssetAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
					TokenAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
				},
				expectedNumOuts: 2,
				expectedAsset:   "f94b5c137c633d352fd5d7fecb3b3c243cdac4b602a4a46f29051350218cb5d7",
				expectedToken:   "e002a216b1d8811c13f195649536bff9d1abd3c7adbe5b2c42d40d0f6eb2e36a",
			},
			{
				args: AddIssuanceArgs{
					Precision:    0,
					AssetAmount:  1000,
					TokenAmount:  0,
					AssetAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
				},
				expectedNumOuts: 1,
				expectedAsset:   "f94b5c137c633d352fd5d7fecb3b3c243cdac4b602a4a46f29051350218cb5d7",
				expectedToken:   "",
			},
		}

		for _, tt := range tests {
			p := newPsetWithInput()
			updater, err := NewUpdater(p)
			if err != nil {
				t.Fatal(err)
			}

			if err := updater.AddIssuance(tt.args); err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, 1, len(p.Inputs))
			assert.Equal(t, tt.expectedNumOuts, len(p.Outputs))

			assetBlindingNonce := p.UnsignedTx.Inputs[0].Issuance.AssetBlindingNonce
			assert.Equal(t, b2h(transaction.Zero[:]), b2h(assetBlindingNonce))

			asset := b2h(elementsutil.ReverseBytes(p.UnsignedTx.Outputs[0].Asset[1:]))
			assert.Equal(t, tt.expectedAsset, asset)

			if tt.args.TokenAmount > 0 {
				token := b2h(elementsutil.ReverseBytes(p.UnsignedTx.Outputs[1].Asset[1:]))
				assert.Equal(t, tt.expectedToken, token)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []AddIssuanceArgs{
			{
				Precision:    9,
				AssetAmount:  1000,
				TokenAmount:  1,
				AssetAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
				TokenAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
			},
			{
				Precision:    0,
				AssetAmount:  1000,
				TokenAmount:  1,
				AssetAddress: "",
				TokenAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
			},
			{
				Precision:    0,
				AssetAmount:  1000,
				TokenAmount:  1,
				AssetAddress: "ert1qvqlg5trrgmsp5mcdtm9wczca5k5l6003jrwf5j",
				TokenAddress: "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
			},
		}

		p := newPsetWithInput()
		updater, err := NewUpdater(p)
		if err != nil {
			t.Fatal(err)
		}

		for _, args := range tests {
			err := updater.AddIssuance(args)
			assert.NotNil(t, err)
		}
	})
}

func TestUpdaterAddReissuance(t *testing.T) {
	// mock of a witnessUtxo. Proofs are slices of zero just for the sake of
	// simplicity. They're need just to recognize the output as confidential
	utxo := &transaction.TxOutput{
		Asset:           h2b("0ac86a00e7d0fabac7aaee22d0709a071d0dc40da7cb76df3eda7e00b0bdd1224f"),
		Script:          h2b("0014603e8a2c6346e01a6f0d5ecaec0b1da5a9fd3df1"),
		Value:           h2b("089a992f8381397fb9df79fc3121612c85925a5b984baed66cab4903710300ef4c"),
		Nonce:           h2b("03f8590c3f339896cdb77a53d4bed6916faa67eb6c624fa124d39bf0d180726d44"),
		RangeProof:      make([]byte, 4174),
		SurjectionProof: make([]byte, 64),
	}

	prevoutHash := "ca584d98e93fece72a7097f4cdefb2372837f2d085061ec87bf3c7d8ca7622cd"
	prevoutIndex := uint32(1)
	prevoutBlinder := h2b("70d9f71278aa15ae9d6750cb29cc329f79a25f6678e14dbeb32913548c228ac9")
	entropy := "1acb83d51ebfe7454cb68718e2bf0665124dd05e525a95ab33b8403e7ff5f6f7"
	assetAmount := uint64(1000)
	tokenAmount := uint64(1)
	cAddr := "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd"

	t.Run("valid", func(t *testing.T) {
		arg := AddReissuanceArgs{
			PrevOutHash:    prevoutHash,
			PrevOutIndex:   prevoutIndex,
			PrevOutBlinder: prevoutBlinder,
			Entropy:        entropy,
			AssetAmount:    assetAmount,
			TokenAmount:    tokenAmount,
			AssetAddress:   cAddr,
			TokenAddress:   cAddr,
			WitnessUtxo:    utxo,
		}

		p := newPsetWithInput()
		updater, err := NewUpdater(p)
		if err != nil {
			t.Fatal(err)
		}

		if err := updater.AddReissuance(arg); err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, 2, len(p.Inputs))
		assert.Equal(t, 2, len(p.Outputs))
		reissuanceNonce :=
			p.UnsignedTx.Inputs[1].Issuance.AssetBlindingNonce
		assert.Equal(t, prevoutBlinder, reissuanceNonce)

		asset := b2h(elementsutil.ReverseBytes(p.UnsignedTx.Outputs[0].Asset[1:]))
		token := b2h(elementsutil.ReverseBytes(p.UnsignedTx.Outputs[1].Asset[1:]))
		expectedToken := "4307771267e443764fdad22b9893c1cbe413dcc736258ebb590a31035f3c143e"
		expectedAsset := "8e80d20a43ee55d5a26d2ac16ea5319c494a193dbb5d2ffc18c7e6b4525f2125"
		assert.Equal(t, expectedAsset, asset)
		assert.Equal(t, expectedToken, token)
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []AddReissuanceArgs{
			{
				PrevOutHash:    "",
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: prevoutBlinder,
				Entropy:        entropy,
				AssetAmount:    assetAmount,
				TokenAmount:    tokenAmount,
				AssetAddress:   cAddr,
				TokenAddress:   cAddr,
				WitnessUtxo:    utxo,
			},
			{
				PrevOutHash:    prevoutHash,
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: nil,
				Entropy:        entropy,
				AssetAmount:    assetAmount,
				TokenAmount:    tokenAmount,
				AssetAddress:   cAddr,
				TokenAddress:   cAddr,
				WitnessUtxo:    utxo,
			},
			{
				PrevOutHash:    prevoutHash,
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: prevoutBlinder,
				Entropy:        "",
				AssetAmount:    assetAmount,
				TokenAmount:    tokenAmount,
				AssetAddress:   cAddr,
				TokenAddress:   cAddr,
				WitnessUtxo:    utxo,
			},
			{
				PrevOutHash:    prevoutHash,
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: prevoutBlinder,
				Entropy:        entropy,
				AssetAmount:    0,
				TokenAmount:    tokenAmount,
				AssetAddress:   cAddr,
				TokenAddress:   cAddr,
				WitnessUtxo:    utxo,
			},
			{
				PrevOutHash:    prevoutHash,
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: prevoutBlinder,
				Entropy:        entropy,
				AssetAmount:    assetAmount,
				TokenAmount:    tokenAmount,
				AssetAddress:   "",
				TokenAddress:   cAddr,
				WitnessUtxo:    utxo,
			},
			{
				PrevOutHash:    prevoutHash,
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: prevoutBlinder,
				Entropy:        entropy,
				AssetAmount:    assetAmount,
				TokenAmount:    tokenAmount,
				AssetAddress:   cAddr,
				TokenAddress:   "",
				WitnessUtxo:    utxo,
			},
			{
				PrevOutHash:    prevoutHash,
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: prevoutBlinder,
				Entropy:        entropy,
				AssetAmount:    assetAmount,
				TokenAmount:    tokenAmount,
				AssetAddress:   "ert1qvqlg5trrgmsp5mcdtm9wczca5k5l6003jrwf5j",
				TokenAddress:   "ert1qvqlg5trrgmsp5mcdtm9wczca5k5l6003jrwf5j",
				WitnessUtxo:    utxo,
			},
			{
				PrevOutHash:    prevoutHash,
				PrevOutIndex:   prevoutIndex,
				PrevOutBlinder: prevoutBlinder,
				Entropy:        entropy,
				AssetAmount:    assetAmount,
				TokenAmount:    tokenAmount,
				AssetAddress:   cAddr,
				TokenAddress:   cAddr,
				WitnessUtxo:    nil,
				NonWitnessUtxo: nil,
			},
		}

		p := newPsetWithInput()
		updater, err := NewUpdater(p)
		if err != nil {
			t.Fatal(err)
		}

		for _, args := range tests {
			assert.NotNil(t, updater.AddReissuance(args))
		}
	})
}

func newPsetWithInput() *Pset {
	in := transaction.NewTxInput(make([]byte, 32), 2)
	inputs := []*transaction.TxInput{in}
	outputs := make([]*transaction.TxOutput, 0)
	p, _ := New(inputs, outputs, 2, 0)
	return p
}
