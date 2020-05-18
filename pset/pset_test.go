package pset

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/transaction"
)

func TestRoundTrip(t *testing.T) {
	tests := struct {
		base64 []string
		hex    []string
	}{
		[]string{
			"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",
		},
		[]string{
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f40000000000000000000000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000000000000",
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f4000000000000000100fd0f010200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6d428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c53259543872e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c401dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000190000000000000010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000100fd5201020000000001e5023b4c497023af19c8a00951f5b689f16dfdd825e2e4239e9f32e40a21fd1f010000006a473044022072e556b51c6e2b15e54762d1577f43f1d40b612d8c0b1fce2e7d07f482a8c93f022031b1f650f1a27f6a39c04dbbe83675e2082b3dbe78ba07fd7a96a6e65a791df0012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000011e188980017a9141d46d41d82f4ed3ef5da0da012ca633fd085ad41870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a6800000000000001030401000000000100fd520102000000000196fe39b21f0d4b0caf61c92c254a818a716d131ece745e6599adea35f849b513000000006a47304402206cb0985a0f149b228a652008c25598f087bbe2f7b0553b14ae0ed6e7ce81068b02205a12dbc5b81b55f966e88a12791fd92fd44f9176dfccf0e956a2bc7d37368999012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5c6980017a914484550d329861ce6830d208fa66613a9511a8a14870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a68000000000000010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0000",
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f4000000000000000100fd0f010200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6d428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c53259543872e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c401dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000019000000000000022020251464420fcc98a2e4cd347afe28a32d769287dacd861476ab858baa43bd308f347304402201e868b2bea22df05229746a27e7df2ca0f584880546f7f6d55dad71cbd50d35302203a04a4cc49fca739c8974c97d3de924c99835e15ad1d85b96ad24ea072d2e63e01010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000100fd5201020000000001e5023b4c497023af19c8a00951f5b689f16dfdd825e2e4239e9f32e40a21fd1f010000006a473044022072e556b51c6e2b15e54762d1577f43f1d40b612d8c0b1fce2e7d07f482a8c93f022031b1f650f1a27f6a39c04dbbe83675e2082b3dbe78ba07fd7a96a6e65a791df0012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000011e188980017a9141d46d41d82f4ed3ef5da0da012ca633fd085ad41870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a680000000000002202026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa47304402201252d7b429dd5fd556fa0962cea9027b924e0919494d3930aa4c0ba41333798402205802cb6163c89644a5ba9830a7a13194a77e71e35593f3ad643b5b20eeee5e7a0101030401000000000100fd520102000000000196fe39b21f0d4b0caf61c92c254a818a716d131ece745e6599adea35f849b513000000006a47304402206cb0985a0f149b228a652008c25598f087bbe2f7b0553b14ae0ed6e7ce81068b02205a12dbc5b81b55f966e88a12791fd92fd44f9176dfccf0e956a2bc7d37368999012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5c6980017a914484550d329861ce6830d208fa66613a9511a8a14870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a680000000000002202026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa47304402207897850961700b54908d4188a483050d7ffe25bcc083f5cd0ce15ce3dfc8a33b022001b7b1dd893290c269f2fab3368e3e6316ef8e85e5efbc9d669b87387ee7c52801010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0000",
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f4000000000000000100fd0f010200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6d428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c53259543872e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c401dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000019000000000000001076a47304402201e868b2bea22df05229746a27e7df2ca0f584880546f7f6d55dad71cbd50d35302203a04a4cc49fca739c8974c97d3de924c99835e15ad1d85b96ad24ea072d2e63e01210251464420fcc98a2e4cd347afe28a32d769287dacd861476ab858baa43bd308f30001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000100fd5201020000000001e5023b4c497023af19c8a00951f5b689f16dfdd825e2e4239e9f32e40a21fd1f010000006a473044022072e556b51c6e2b15e54762d1577f43f1d40b612d8c0b1fce2e7d07f482a8c93f022031b1f650f1a27f6a39c04dbbe83675e2082b3dbe78ba07fd7a96a6e65a791df0012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000011e188980017a9141d46d41d82f4ed3ef5da0da012ca633fd085ad41870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a6800000000000001076a47304402201252d7b429dd5fd556fa0962cea9027b924e0919494d3930aa4c0ba41333798402205802cb6163c89644a5ba9830a7a13194a77e71e35593f3ad643b5b20eeee5e7a0121026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa000100fd520102000000000196fe39b21f0d4b0caf61c92c254a818a716d131ece745e6599adea35f849b513000000006a47304402206cb0985a0f149b228a652008c25598f087bbe2f7b0553b14ae0ed6e7ce81068b02205a12dbc5b81b55f966e88a12791fd92fd44f9176dfccf0e956a2bc7d37368999012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5c6980017a914484550d329861ce6830d208fa66613a9511a8a14870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a6800000000000001076a47304402207897850961700b54908d4188a483050d7ffe25bcc083f5cd0ce15ce3dfc8a33b022001b7b1dd893290c269f2fab3368e3e6316ef8e85e5efbc9d669b87387ee7c5280121026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa0001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0000",
		},
	}

	for _, str := range tests.base64 {
		p, err := NewPsetFromBase64(str)
		if err != nil {
			t.Fatal(err)
		}
		res, err := p.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		if res != str {
			t.Fatalf("Got: %s, expected: %s", res, str)
		}
	}

	for _, str := range tests.hex {
		p, err := NewPsetFromHex(str)
		if err != nil {
			t.Fatal(err)
		}
		res, err := p.ToHex()
		if err != nil {
			t.Fatal(err)
		}
		if res != str {
			t.Fatalf("Got: %s, expected: %s", res, str)
		}
	}
}

func TestCreator(t *testing.T) {
	file, err := ioutil.ReadFile("data/creator.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []map[string]interface{}
	err = json.Unmarshal(file, &tests)

	for _, v := range tests {
		inputs := []*transaction.TxInput{}
		for _, vIn := range v["inputs"].([]interface{}) {
			in := vIn.(map[string]interface{})
			inHash, _ := hex.DecodeString(in["hash"].(string))
			inIndex := uint32(in["index"].(float64))
			inHash = reverseBytes(inHash)
			inputs = append(inputs, transaction.NewTxInput(inHash, inIndex))
		}

		outputs := []*transaction.TxOutput{}
		for _, vOut := range v["outputs"].([]interface{}) {
			out := vOut.(map[string]interface{})
			outAsset, _ := hex.DecodeString(out["asset"].(string))
			outAsset = append([]byte{0x01}, reverseBytes(outAsset)...)
			outValue, _ := toConfidentialValue(int(out["value"].(float64)))
			outScript, _ := hex.DecodeString(out["script"].(string))
			outputs = append(outputs, transaction.NewTxOutput(outAsset, outValue, outScript))
		}

		p, err := New(inputs, outputs, 2, 0)
		if err != nil {
			t.Fatal(err)
		}

		base64Res, err := p.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		hexRes, err := p.ToHex()
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
				asset = append([]byte{0x01}, reverseBytes(asset)...)
				script, _ := hex.DecodeString(wu["script"].(string))
				value, _ := toConfidentialValue(int(wu["value"].(float64)))
				utxo := transaction.NewTxOutput(asset, value, script)
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

		base64Res, err := updater.Upsbt.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		hexRes, err := updater.Upsbt.ToHex()
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

func TestSigner(t *testing.T) {
	file, err := ioutil.ReadFile("data/signer.json")
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
			signature, _ := hex.DecodeString(in["signature"].(string))
			pubkey, _ := hex.DecodeString(in["pubkey"].(string))
			updater.Sign(inIndex, signature, pubkey, p.Inputs[inIndex].RedeemScript, p.Inputs[inIndex].WitnessScript)
		}

		base64Res, err := updater.Upsbt.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		hexRes, err := updater.Upsbt.ToHex()
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

func TestFinalizer(t *testing.T) {
	file, err := ioutil.ReadFile("data/finalizer.json")
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

		err = FinalizeAll(p)
		if err != nil {
			t.Fatal(err)
		}

		base64Res, err := p.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		hexRes, err := p.ToHex()
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

func TestExtractor(t *testing.T) {
	file, err := ioutil.ReadFile("data/extractor.json")
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

		tx, err := Extract(p)
		if err != nil {
			t.Fatal(err)
		}
		res, err := tx.ToHex()
		if err != nil {
			t.Fatal(err)
		}

		expectedTxHex := v["expectedTxHex"].(string)
		if res != expectedTxHex {
			t.Fatalf("Got: %s, expected: %s", res, expectedTxHex)
		}
	}
}

func toConfidentialValue(val int) ([]byte, error) {
	unconfPrefix := byte(1)
	b := bytes.NewBuffer([]byte{})
	if err := transaction.BinarySerializer.PutUint64(b, binary.LittleEndian, uint64(val)); err != nil {
		return nil, err
	}
	return append([]byte{unconfPrefix}, reverseBytes(b.Bytes())...), nil
}
