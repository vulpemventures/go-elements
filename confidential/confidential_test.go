package confidential

import (
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-secp256k1-zkp"
	"io/ioutil"
	"strconv"
	"testing"
)

var tests map[string]interface{}

func setUp() error {
	file, err := ioutil.ReadFile("data/confidential.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(file, &tests)
	if err != nil {
		return err
	}

	return nil
}

func TestUnblindOutput(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["unblindOutput"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		scriptPubkeyStr := v["scriptPubkey"].(string)
		assetGeneratorStr := v["assetGenerator"].(string)
		blindingPrivkeyStr := v["blindingPrivkey"].(string)
		ephemeralPubkeyStr := v["ephemeralPubkey"].(string)
		valueCommitmentStr := v["valueCommitment"].(string)
		rangeproofStr := v["rangeproof"].(string)

		ephemeralPubkey, err := hex.DecodeString(ephemeralPubkeyStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		blindingPrivkey, err := hex.DecodeString(blindingPrivkeyStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		rangeproof, err := hex.DecodeString(rangeproofStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		commitment, err := secp256k1.CommitmentFromString(valueCommitmentStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assetGenerator, err := hex.DecodeString(assetGeneratorStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		scriptPubkey, err := hex.DecodeString(scriptPubkeyStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		input := UnblindInput{
			EphemeralPubkey: ephemeralPubkey,
			BlindingPrivkey: blindingPrivkey,
			Rangeproof:      rangeproof,
			ValueCommit:     *commitment,
			Asset:           assetGenerator,
			ScriptPubkey:    scriptPubkey,
		}

		output, err := UnblindOutput(input)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expected := v["expected"].(map[string]interface{})

		valueStr := expected["value"].(string)
		value, err := strconv.Atoi(valueStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assetStr := expected["asset"].(string)
		valueBlindingFactor := expected["valueBlindingFactor"].(string)
		assetBlindingFactor := expected["assetBlindingFactor"].(string)

		assert.Equal(t, output.Value, uint64(value))
		assert.Equal(t, hex.EncodeToString(output.AssetBlindingFactor), assetBlindingFactor)
		assert.Equal(t, hex.EncodeToString(output.Asset), assetStr)
		assert.Equal(t, hex.EncodeToString(output.ValueBlindingFactor[:]), valueBlindingFactor)
	}
}

func TestFinalValueBlindingFactor(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["finalValueBlindingFactor"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		inValuesSlice := v["inValues"].([]interface{})
		inValues := make([]uint64, 0)
		for _, val := range inValuesSlice {
			n, err := strconv.ParseUint(val.(string), 10, 64)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			inValues = append(inValues, n)
		}

		outValuesSlice := v["outValues"].([]interface{})
		outValues := make([]uint64, 0)
		for _, val := range outValuesSlice {
			n, err := strconv.ParseUint(val.(string), 10, 64)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			outValues = append(outValues, n)
		}

		inGeneratorsSlice := v["inGenerators"].([]interface{})
		inGenerators := make([][]byte, 0)
		for _, val := range inGeneratorsSlice {
			gen, err := hex.DecodeString(val.(string))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			inGenerators = append(inGenerators, gen)
		}

		outGeneratorsSlice := v["outGenerators"].([]interface{})
		outGenerators := make([][]byte, 0)
		for _, val := range outGeneratorsSlice {
			gen, err := hex.DecodeString(val.(string))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			outGenerators = append(outGenerators, gen)
		}

		inFactorsSlice := v["inFactors"].([]interface{})
		inFactors := make([][]byte, 0)
		for _, val := range inFactorsSlice {
			gen, err := hex.DecodeString(val.(string))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			inFactors = append(inFactors, gen)
		}

		outFactorsSlice := v["outFactors"].([]interface{})
		outFactors := make([][]byte, 0)
		for _, val := range outFactorsSlice {
			gen, err := hex.DecodeString(val.(string))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			outFactors = append(outFactors, gen)
		}

		input := FinalValueBlindingFactorInput{
			InValues:      inValues,
			OutValues:     outValues,
			InGenerators:  inGenerators,
			OutGenerators: outGenerators,
			InFactors:     inFactors,
			OutFactors:    outFactors,
		}

		factor, err := FinalValueBlindingFactor(input)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expectedFactor := v["expected"].(string)
		assert.Equal(t, expectedFactor, hex.EncodeToString(factor[:]))
	}
}

func TestSurjectionProof(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["surjectionProof"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		seedStr := v["seed"].(string)
		seed, err := hex.DecodeString(seedStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		outputAssetStr := v["outputAsset"].(string)
		outputAsset, err := hex.DecodeString(outputAssetStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		outputAssetBlindingFactorStr := v["outputAssetBlindingFactor"].(string)
		outputAssetBlindingFactor, err := hex.DecodeString(outputAssetBlindingFactorStr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		inputAssetsSlice := v["inputAssets"].([]interface{})
		inputAssets := make([][]byte, 0)
		for _, val := range inputAssetsSlice {
			a, err := hex.DecodeString(val.(string))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			inputAssets = append(inputAssets, a)
		}

		inputAssetBlindingFactorsSlice := v["inputAssetBlindingFactors"].([]interface{})
		inputAssetBlindingFactors := make([][]byte, 0)
		for _, val := range inputAssetBlindingFactorsSlice {
			a, err := hex.DecodeString(val.(string))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			inputAssetBlindingFactors = append(inputAssetBlindingFactors, a)
		}

		input := SurjectionProofInput{
			OutputAsset:               outputAsset,
			OutputAssetBlindingFactor: outputAssetBlindingFactor,
			InputAssets:               inputAssets,
			InputAssetBlindingFactors: inputAssetBlindingFactors,
			Seed:                      seed,
		}

		factor, err := SurjectionProof(input)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expectedFactor := v["expected"].(string)
		assert.Equal(t, expectedFactor, hex.EncodeToString(factor[:]))

	}

}
