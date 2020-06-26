package pset

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

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
