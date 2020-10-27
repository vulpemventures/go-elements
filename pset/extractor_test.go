package pset

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/vulpemventures/go-elements/transaction"
)

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

func ExampleExtract() {
	inputs := []*transaction.TxInput{}
	outputs := []*transaction.TxOutput{}
	p, err := New(inputs, outputs, 2, 0)
	updater, err := NewUpdater(p)
	pset := updater.Data

	finalTx, err := Extract(pset)
}
