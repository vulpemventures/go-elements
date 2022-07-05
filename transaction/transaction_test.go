package transaction

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/elementsutil"
)

func TestRoundTrip(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, str := range tests["txRoundTrip"].([]interface{}) {
		tx, err := NewTxFromHex(str.(string))
		if err != nil {
			t.Fatal(err)
		}
		res, err := tx.ToHex()
		if err != nil {
			t.Fatal(err)
		}
		if res != str {
			t.Fatalf("Got: %s, expected: %s", res, str)
		}
	}
}

func TestAddInput(t *testing.T) {
	hashStr := "ffffffff00ffff000000000000000000000000000000000000000000101010ff"
	index := uint32(0)

	tx := &Transaction{}
	hash, _ := hex.DecodeString(hashStr)
	txIn := NewTxInput(hash, index)
	tx.AddInput(txIn)

	input := tx.Inputs[0]
	if !reflect.DeepEqual(input.Hash, hash) {
		t.Fatalf("Got %x, expected %s", input.Hash, hashStr)
	}
	if input.Index != 0 {
		t.Fatalf("Got %d, expected %d", input.Index, index)
	}
	if input.Sequence != DefaultSequence {
		t.Fatalf("Got %d, expected %d", input.Sequence, DefaultSequence)
	}
}

func TestAddOutput(t *testing.T) {
	assetStr := "01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d"
	value := []byte{0x00}
	script := []byte{}

	tx := &Transaction{}
	asset, _ := hex.DecodeString(assetStr)
	txOut := NewTxOutput(asset, value, script)
	tx.AddOutput(txOut)
	output := tx.Outputs[0]
	if !reflect.DeepEqual(output.Asset, asset) {
		t.Fatalf("Got %x, expected %s", output.Asset, assetStr)
	}
	if !reflect.DeepEqual(output.Value, value) {
		t.Fatalf("Got %x, expected %x", output.Value, value)
	}
	if !reflect.DeepEqual(output.Script, script) {
		t.Fatalf("Got %x, expected %x", output.Script, script)
	}
}

func TestTxHash(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, v := range tests["txHash"].([]interface{}) {
		testVector := v.(map[string]interface{})
		tx, err := NewTxFromHex(testVector["txHex"].(string))
		if err != nil {
			t.Fatal(err)
		}

		expectedTxHash := testVector["expectedTxHash"].(string)
		expectedTxWitnessHash := testVector["expectedTxWitnessHash"].(string)
		if tx.TxHash().String() != expectedTxHash {
			t.Fatalf("Got: %s, expected: %s", tx.TxHash().String(), expectedTxHash)
		}
		if tx.WitnessHash().String() == expectedTxWitnessHash {
			t.Fatalf("Got: %s, expected: %s", tx.WitnessHash().String(), expectedTxWitnessHash)
		}
	}
}

func TestSize(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, v := range tests["txSize"].([]interface{}) {
		testVector := v.(map[string]interface{})
		tx, err := NewTxFromHex(testVector["txHex"].(string))
		if err != nil {
			t.Fatal(err)
		}

		expectedWeight := int(testVector["expectedWeight"].(float64))
		expectedVsize := int(testVector["expectedVsize"].(float64))
		if res := tx.Weight(); res != expectedWeight {
			t.Fatalf("Got: %d, expected: %d", res, expectedWeight)
		}
		if res := tx.VirtualSize(); res != expectedVsize {
			t.Fatalf("Got: %d, expected: %d", res, expectedVsize)
		}
	}
}

func TestCopy(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, str := range tests["txCopy"].([]interface{}) {
		tx, err := NewTxFromHex(str.(string))
		if err != nil {
			t.Fatal(err)
		}
		newTx := tx.Copy()
		txHex, _ := tx.ToHex()
		newTxHex, _ := newTx.ToHex()
		if txHex != newTxHex {
			t.Fatal("Should have value equality")
		}
		if newTx == tx {
			t.Fatal("Should not have reference equality")
		}
	}
}

func TestHashForSignature(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, v := range tests["txHashForSignature"].([]interface{}) {
		testVector := v.(map[string]interface{})
		tx, err := NewTxFromHex(testVector["txHex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		inIndex := int(testVector["inIndex"].(float64))
		script, _ := hex.DecodeString(testVector["script"].(string))
		hashType := txscript.SigHashType(testVector["hashType"].(float64))
		hash, err := tx.HashForSignature(inIndex, script, hashType)
		if err != nil {
			t.Fatal(err)
		}
		expectedHash := testVector["expectedHash"].(string)
		if res := hex.EncodeToString(hash[:]); res != expectedHash {
			t.Fatalf("Got: %s, expected: %s", res, expectedHash)
		}
	}
}

func TestHashForWitnessV0(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, v := range tests["txHashForWitnessV0"].([]interface{}) {
		testVector := v.(map[string]interface{})
		tx, err := NewTxFromHex(testVector["txHex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		inIndex := int(testVector["inIndex"].(float64))
		script, _ := hex.DecodeString(testVector["script"].(string))
		hashType := txscript.SigHashType(testVector["hashType"].(float64))
		value, _ := elementsutil.ValueToBytes(uint64(testVector["amount"].(float64)))

		hash := tx.HashForWitnessV0(inIndex, script, value[:], hashType)
		expectedHash := testVector["expectedHash"].(string)
		if res := hex.EncodeToString(hash[:]); res != expectedHash {
			t.Fatalf("Got: %s, expected: %s", res, expectedHash)
		}
	}
}

func TestHashForWitnessV1(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, v := range tests["txHashForWitnessV1"].([]interface{}) {
		testVector := v.(map[string]interface{})
		t.Run(testVector["description"].(string), func(tt *testing.T) {
			tx, err := NewTxFromHex(testVector["txHex"].(string))
			if err != nil {
				tt.Fatal(err)
			}

			scripts := make([][]byte, 0)
			assets := make([][]byte, 0)
			values := make([][]byte, 0)

			prevouts := testVector["prevouts"].([]interface{})
			for _, prevout := range prevouts {
				prev := prevout.(map[string]interface{})
				scriptBytes, _ := hex.DecodeString(prev["script"].(string))
				valueBytes, _ := hex.DecodeString(prev["value"].(string))
				assetBytes, _ := hex.DecodeString(prev["asset"].(string))
				prefix := byte(0x01)
				if len(valueBytes) != 9 {
					prefix = 0x0a
				}

				assetBytes = append([]byte{prefix}, elementsutil.ReverseBytes(assetBytes)...)
				scripts = append(scripts, scriptBytes)
				assets = append(assets, assetBytes)
				values = append(values, valueBytes)
			}

			inIndex := testVector["inIndex"].(float64)
			genesisHash, _ := chainhash.NewHashFromStr(testVector["genesisHash"].(string))

			hashType := txscript.SigHashType(testVector["type"].(float64))
			var leafHash *chainhash.Hash = nil
			if testVector["leafHash"] != nil {
				leafHashBytes, _ := hex.DecodeString(testVector["leafHash"].(string))
				leafHash, _ = chainhash.NewHash(leafHashBytes)
			}

			hash := tx.HashForWitnessV1(int(inIndex), scripts, assets, values, hashType, genesisHash, leafHash, nil)
			expectedHash := testVector["expectedHash"].(string)
			if res := hex.EncodeToString(hash[:]); res != expectedHash {
				tt.Fatalf("Got: %s, expected: %s", res, expectedHash)
			}
		})
	}
}
