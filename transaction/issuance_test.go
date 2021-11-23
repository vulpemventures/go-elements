package transaction

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/elementsutil"
)

func TestIssuanceGeneration(t *testing.T) {
	file, err := ioutil.ReadFile("data/issuance.json")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, testVector := range tests["valid"].([]interface{}) {
		v := testVector.(map[string]interface{})

		inTxHash, _ := hex.DecodeString(v["txHash"].(string))
		inIndex := uint32(v["index"].(float64))
		assetAmount := uint64(v["assetAmount"].(float64))
		tokenAmount := uint64(v["tokenAmount"].(float64))
		tokenFlag := uint(v["tokenFlag"].(float64))
		precision := uint(v["precision"].(float64))

		var contract *IssuanceContract
		if v["contract"] != nil {
			var c IssuanceContract
			contractBytes, _ := json.Marshal(v["contract"].(interface{}))
			json.Unmarshal(contractBytes, &c)
			contract = &c
		}

		issuance, err := NewTxIssuance(
			assetAmount,
			tokenAmount,
			precision,
			contract,
		)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		resAssetAmount, _ := elementsutil.ElementsToSatoshiValue(
			issuance.TxIssuance.AssetAmount,
		)
		resTokenAmount, _ := elementsutil.ElementsToSatoshiValue(
			issuance.TxIssuance.TokenAmount,
		)
		assert.Equal(t, uint64(v["expectedAssetAmount"].(float64)), resAssetAmount)
		assert.Equal(t, uint64(v["expectedTokenAmount"].(float64)), resTokenAmount)

		err = issuance.GenerateEntropy(elementsutil.ReverseBytes(inTxHash), inIndex)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(t, v["expectedEntropy"].(string), hex.EncodeToString(issuance.AssetEntropy))

		asset, err := issuance.GenerateAsset()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(
			t,
			v["expectedAsset"].(string),
			hex.EncodeToString(elementsutil.ReverseBytes(asset)),
		)

		token, err := issuance.GenerateReissuanceToken(tokenFlag)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(
			t,
			v["expectedToken"].(string),
			hex.EncodeToString(elementsutil.ReverseBytes(token)),
		)
	}
}

func TestIsContractHashValid(t *testing.T) {
	contract := IssuanceContract{
		Name:      "Tiero Token",
		Ticker:    "TIERO",
		Version:   0,
		Precision: 8,
		PubKey:    "02a9a7399de89ec2e7de876bbe0b512f78f13d5d0a3315047e5b14109c8bac38f2",
		Entity: IssuanceEntity{
			Domain: "tiero.github.io",
		},
	}

	issuance, err := NewTxIssuance(10, 2, 8, &contract)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(
		t,
		"d5c4363ee9cf2a4319c2f0ccc04cdb83d6213e4d26d94d70003c58eaf2473866",
		hex.EncodeToString(elementsutil.ReverseBytes(issuance.ContractHash)), //validate online with reverse contract hash
	)
	assert.Equal(
		t,
		"663847f2ea583c00704dd9264d3e21d683db4cc0ccf0c219432acfe93e36c4d5",
		hex.EncodeToString(issuance.ContractHash),
	)
}
