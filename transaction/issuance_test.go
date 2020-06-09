package transaction

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

func TestIssuanceGenerateEntropy(t *testing.T) {
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
		var contract *IssuanceContract
		if v["contract"] != nil {
			c := v["contract"].(IssuanceContract)
			contract = &c
		}

		issuance, err := NewTxIssuance(assetAmount, tokenAmount)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		err = issuance.GenerateEntropy(bufferutil.ReverseBytes(inTxHash), inIndex, contract)
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
