package transaction

import (
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-secp256k1-zkp"
	"io/ioutil"
	"strconv"
	"testing"
)

func TestUnblindOutput(t *testing.T) {
	file, err := ioutil.ReadFile("data/confidential.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests map[string]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Error(err)
	}

	vectors := tests["unblind"].([]interface{})

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		scriptPubkeyStr := v["scriptPubkey"].(string)
		assetGeneratorStr := v["assetGenerator"].(string)
		blindingPrivkeyStr := v["blindingPrivkey"].(string)
		ephemeralPubkeyStr := v["ephemeralPubkey"].(string)
		valueCommitmentStr := v["valueCommitment"].(string)
		rangeproofStr := v["rangeproof"].(string)

		ephemeralPubkey, err := hex.DecodeString(ephemeralPubkeyStr)
		assert.NoError(t, err)

		blindingPrivkey, err := hex.DecodeString(blindingPrivkeyStr)
		assert.NoError(t, err)

		rangeproof, err := hex.DecodeString(rangeproofStr)
		assert.NoError(t, err)

		commitment, err := secp256k1.CommitmentFromString(valueCommitmentStr)
		assert.NoError(t, err)

		assetGenerator, err := hex.DecodeString(assetGeneratorStr)
		assert.NoError(t, err)

		scriptPubkey, err := hex.DecodeString(scriptPubkeyStr)
		assert.NoError(t, err)

		input := UnblindInput{
			EphemeralPubkey: ephemeralPubkey,
			BlindingPrivkey: blindingPrivkey,
			Rangeproof:      rangeproof,
			ValueCommit:     *commitment,
			Asset:           assetGenerator,
			ScriptPubkey:    scriptPubkey,
		}

		output, err := UnblindOutput(input)
		assert.NoError(t, err)

		expected := v["expected"].(map[string]interface{})

		valueStr := expected["value"].(string)
		value, err := strconv.Atoi(valueStr)
		assert.NoError(t, err)

		assetStr := expected["asset"].(string)
		valueBlindingFactor := expected["valueBlindingFactor"].(string)
		assetBlindingFactor := expected["assetBlindingFactor"].(string)

		assert.Equal(t, output.Value, uint64(value))
		assert.Equal(t, hex.EncodeToString(output.AssetBlindingFactor), assetBlindingFactor)
		assert.Equal(t, hex.EncodeToString(output.Asset), assetStr)
		assert.Equal(t, hex.EncodeToString(output.ValueBlindingFactor[:]), valueBlindingFactor)
	}
}
