package pset

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/transaction"
)

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
			inHash = bufferutil.ReverseBytes(inHash)
			inputs = append(inputs, transaction.NewTxInput(inHash, inIndex))
		}

		outputs := []*transaction.TxOutput{}
		for _, vOut := range v["outputs"].([]interface{}) {
			out := vOut.(map[string]interface{})
			outAsset, _ := hex.DecodeString(out["asset"].(string))
			outAsset = append([]byte{0x01}, bufferutil.ReverseBytes(outAsset)...)
			outValue, _ := confidential.SatoshiToElementsValue(uint64(out["value"].(float64)))
			outScript, _ := hex.DecodeString(out["script"].(string))
			outputs = append(outputs, transaction.NewTxOutput(outAsset, outValue[:], outScript))
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
