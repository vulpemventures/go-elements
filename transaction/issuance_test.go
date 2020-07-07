package transaction

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
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

		amount := [9]byte{}
		copy(amount[:], issuance.TxIssuance.AssetAmount)
		resAssetAmount, _ := confidential.ElementsToSatoshiValue(
			amount,
		)
		copy(amount[:], issuance.TxIssuance.TokenAmount)
		resTokenAmount, _ := confidential.ElementsToSatoshiValue(
			amount,
		)
		assert.Equal(t, uint64(v["expectedAssetAmount"].(float64)), resAssetAmount)
		assert.Equal(t, uint64(v["expectedTokenAmount"].(float64)), resTokenAmount)

		err = issuance.GenerateEntropy(bufferutil.ReverseBytes(inTxHash), inIndex)
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
			hex.EncodeToString(bufferutil.ReverseBytes(asset)),
		)

		token, err := issuance.GenerateReissuanceToken(tokenFlag)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(
			t,
			v["expectedToken"].(string),
			hex.EncodeToString(bufferutil.ReverseBytes(token)),
		)
	}
}
