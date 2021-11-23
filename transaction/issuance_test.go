package transaction

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
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

type Payload struct {
	Contract     IssuanceContract `json:"contract"`
	ContractHash string           `json:"contract_hash"`
}

func TestIsContractHashValid(t *testing.T) {
	contract := IssuanceContract{
		Name:      "Tiero Token",
		Ticker:    "TIERO",
		Version:   0,
		Precision: 8,
		PubKey:    "02a9a7399de89ec2e7de876bbe0b512f78f13d5d0a3315047e5b14109c8bac38f2",
		Entity: IssuanceEntity{
			Domain: "www.domain",
		},
	}

	issuance, err := NewTxIssuance(10, 2, 8, &contract)
	if err != nil {
		t.Fatal(err)
	}

	data := Payload{
		Contract:     contract,
		ContractHash: hex.EncodeToString(issuance.ContractHash),
	}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewReader(payloadBytes)

	req, err := http.NewRequest("POST", "https://assets.blockstream.info/contract/validate", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	bodyResp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "valid", string(bodyResp))
}
