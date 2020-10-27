package pset

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/vulpemventures/go-elements/transaction"
)

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

func ExampleMaybeFinalize() {
	inputs := []*transaction.TxInput{}
	outputs := []*transaction.TxOutput{}
	p, err := New(inputs, outputs, 2, 0)
	updater, err := NewUpdater(p)
	pset := updater.Data

	boolean = MaybeFinalize(pset, 0)
}

func ExampleMaybeFinalizeAll() {
	inputs := []*transaction.TxInput{}
	outputs := []*transaction.TxOutput{}
	p, err := New(inputs, outputs, 2, 0)
	updater, err := NewUpdater(p)
	pset := updater.Data

	err = FinalizeAll(pset)
}

func ExampleFinalizeAll() {
	inputs := []*transaction.TxInput{}
	outputs := []*transaction.TxOutput{}
	p, err := New(inputs, outputs, 2, 0)
	updater, err := NewUpdater(p)
	pset := updater.Data

	err = FinalizeAll(pset)
}

func ExampleFinalize() {
	inputs := []*transaction.TxInput{}
	outputs := []*transaction.TxOutput{}
	p, err := New(inputs, outputs, 2, 0)
	updater, err := NewUpdater(p)
	pset := updater.Data

	err := FinalizeAll(pset)
}
