package transaction

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/vulpemventures/go-elements/network"

	"github.com/stretchr/testify/assert"

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
		value, _ := elementsutil.SatoshiToElementsValue(uint64(testVector["amount"].(float64)))

		hash := tx.HashForWitnessV0(inIndex, script, value[:], hashType)
		expectedHash := testVector["expectedHash"].(string)
		if res := hex.EncodeToString(hash[:]); res != expectedHash {
			t.Fatalf("Got: %s, expected: %s", res, expectedHash)
		}
	}
}

//TODO remove
func TestT(t *testing.T) {
	txHex := "000000000101f9121cd59a4b78dddc7c9f83bcd67673793091e3a2bbd1dcb23b9827fc536fe700000040220020a62164dc2a1b4d7f6c745e7f26aa291c7cca593ee90be38ca0f74563e4cbd3b8ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e0f000160014b9a5305fdb348e083f9e7ba2a3f525361365c0220125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e0f000000000000000000220e5f75e2001451c9e26afcceabbf0d1b27d49dc9a49e167b1e454834baade43c0475221029478c260f0437a59a251018b9d2cbd7093ce2b8febd016ee70f071f92f82860a210248eaf21ce6f63de98b1a670932dad6e6fab30b251d932fcb195cd3548afe875852ae060800e1f50500000000210125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a200f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e22061600145a2707d388a709bdbc835c0b9e3a4e09c0480cfb8a02000000013b69feea417d56a57b5627e912b98272035f38f74f11a8ad745b93075615121b000000001716001442426399d0c38a8924ac4b159a1e7c8b68561c69feffffff0200e1f5050000000017a914b1c2397229cde36bae6f93d3d27f0fe65c537c0787c464e90b0000000017a914060aa002813c7a418e5efce539ab11c043aa55318749000000970000003061b271e0f0513058f394d680ea995630ca3538ccd8de4ab917ac2dc23241c2057b425aad40cc6a8064000206d5461a5a68c624fe192a340a4c2b2010a1e8baa0fa4fa660ffff7f20020000000200000002ae72115b60b706b1f51e873e1558d68fd3c2277c3a75e0bbc37f5b4521948cc0f9121cd59a4b78dddc7c9f83bcd67673793091e3a2bbd1dcb23b9827fc536fe7010500000000"
	tx, err := NewTxFromHex(txHex)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(tx)
}

//TODO remove
func TestValue(t *testing.T) {
	valStr := "00e1f50500000000"

	val, err := hex.DecodeString(valStr)
	if err != nil {
		t.Fatal(err)
	}

	valRev := elementsutil.ReverseBytes(val[:])
	finalVal := append([]byte{0x01}, valRev...)

	satoshiValue, err := elementsutil.ElementsToSatoshiValue(finalVal)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	fmt.Println(satoshiValue)

	valueBytes, err := elementsutil.SatoshiToElementsValue(satoshiValue)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	revValueBytes := elementsutil.ReverseBytes(valueBytes[:])

	finStr := hex.EncodeToString(revValueBytes[:len(revValueBytes)-1])
	assert.Equal(t, valStr, finStr)
}

func TestValueReverse(t *testing.T) {
	valueBytes, err := elementsutil.SatoshiToElementsValue(uint64(100000000))
	if err != nil {
		t.FailNow()
	}

	revValueBytes := elementsutil.ReverseBytes(valueBytes[:])

	valToStore := revValueBytes[:len(revValueBytes)-1]

	finStr := hex.EncodeToString(valToStore)
	assert.Equal(t, "00e1f50500000000", finStr)
}

func TestAssetReverse(t *testing.T) {
	asset := network.Regtest.AssetID
	assetBytes, err := hex.DecodeString(asset)
	if err != nil {
		t.Fatal(err)
	}

	revValueBytes := elementsutil.ReverseBytes(assetBytes[:])

	valToStore := revValueBytes[:len(revValueBytes)-1]

	finStr := hex.EncodeToString(valToStore)
	fmt.Println(finStr)
}

func TestAsset(t *testing.T) {
	valStr := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

	val, err := hex.DecodeString(valStr)
	if err != nil {
		t.Fatal(err)
	}

	valRev := elementsutil.ReverseBytes(val[:])

	fmt.Println(hex.EncodeToString(valRev))

	//revValueBytes := elementsutil.ReverseBytes(valRev[:])
	//
	//finStr := hex.EncodeToString(revValueBytes[:len(revValueBytes)-1])
	//fmt.Println(finStr)
	//assert.Equal(t, valStr, finStr)
}

func TestTT(t *testing.T) {
	peggedAssetBytes, err := hex.DecodeString(network.Regtest.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	var lbtc = append(
		[]byte{0x01},
		elementsutil.ReverseBytes(peggedAssetBytes)...,
	)
	fmt.Println(fmt.Sprintf("peggedAsset: %v", hex.EncodeToString(lbtc)))
	fmt.Println(hex.EncodeToString(lbtc[1:]))

	//parentBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	//parentBlockHashBytes, err := hex.DecodeString(parentBlockHash)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(fmt.Sprintf("parentBlockHash: %v", hex.EncodeToString(parentBlockHashBytes)))
}
