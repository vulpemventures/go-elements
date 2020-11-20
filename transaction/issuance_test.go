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
