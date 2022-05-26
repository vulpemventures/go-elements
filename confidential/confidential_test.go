package confidential

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/transaction"
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

func h2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}

func TestUnblindOutput(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["unblindOutput"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		nonce := h2b(v["ephemeralPubkey"].(string))
		blindingPrivkey := h2b(v["blindingPrivkey"].(string))
		rangeproof := h2b(v["rangeproof"].(string))
		valueCommitment := h2b(v["valueCommitment"].(string))
		assetCommitment := h2b(v["assetGenerator"].(string))
		scriptPubkey := h2b(v["scriptPubkey"].(string))

		txOut := &transaction.TxOutput{
			Nonce:           nonce,
			RangeProof:      rangeproof,
			Value:           valueCommitment,
			Asset:           assetCommitment,
			Script:          scriptPubkey,
			SurjectionProof: make([]byte, 64), // not important, we can zero this
		}

		output, err := UnblindOutputWithKey(txOut, blindingPrivkey)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expected := v["expected"].(map[string]interface{})
		value, _ := strconv.Atoi(expected["value"].(string))
		assetStr := expected["asset"].(string)
		valueBlindingFactor := expected["valueBlindingFactor"].(string)
		assetBlindingFactor := expected["assetBlindingFactor"].(string)

		assert.Equal(t, uint64(value), output.Value)
		assert.Equal(t, assetBlindingFactor, hex.EncodeToString(output.AssetBlindingFactor))
		assert.Equal(t, assetStr, hex.EncodeToString(output.Asset))
		assert.Equal(t, valueBlindingFactor, hex.EncodeToString(output.ValueBlindingFactor[:]))
	}
}

func TestUnblindIssuance(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["unblindIssuance"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		inHash := h2b(v["inHash"].(string))
		inIndex := uint32(v["inIndex"].(float64))
		assetBlindingNonce := h2b(v["nonce"].(string))
		assetEntropy := h2b(v["entropy"].(string))
		assetAmountCommitment := h2b(v["assetAmountCommitment"].(string))
		tokenAmountCommitment := h2b(v["tokenAmountCommitment"].(string))
		assetRangeProof := h2b(v["assetRangeProof"].(string))
		tokenRangeProof := h2b(v["tokenRangeProof"].(string))

		b := v["blindingPrvKeys"].(map[string]interface{})
		blindKeys := [][]byte{h2b(b["asset"].(string)), h2b(b["token"].(string))}

		txIn := &transaction.TxInput{
			Hash:  inHash,
			Index: inIndex,
			Issuance: &transaction.TxIssuance{
				AssetBlindingNonce: assetBlindingNonce,
				AssetEntropy:       assetEntropy,
				AssetAmount:        assetAmountCommitment,
				TokenAmount:        tokenAmountCommitment,
			},
			IssuanceRangeProof:  assetRangeProof,
			InflationRangeProof: tokenRangeProof,
		}

		unblinded, err := UnblindIssuance(txIn, blindKeys)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expected := v["expected"].(map[string]interface{})
		for key := range expected {
			var want map[string]interface{}
			var got *UnblindOutputResult
			if key == "asset" {
				want = expected["asset"].(map[string]interface{})
				got = unblinded.Asset
			} else {
				want = expected["token"].(map[string]interface{})
				got = unblinded.Token
			}

			value, _ := strconv.Atoi(want["value"].(string))
			asset := want["asset"].(string)
			valueBlindingFactor := want["valueBlindingFactor"].(string)
			assetBlindingFactor := want["assetBlindingFactor"].(string)

			assert.Equal(t, uint64(value), got.Value)
			assert.Equal(t, valueBlindingFactor, hex.EncodeToString(got.ValueBlindingFactor))
			assert.Equal(t, asset, hex.EncodeToString(got.Asset))
			assert.Equal(t, assetBlindingFactor, hex.EncodeToString(got.AssetBlindingFactor))
		}
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
		inValues := make([]uint64, 0, len(inValuesSlice))
		for _, val := range inValuesSlice {
			n, _ := strconv.ParseUint(val.(string), 10, 64)
			inValues = append(inValues, n)
		}

		outValuesSlice := v["outValues"].([]interface{})
		outValues := make([]uint64, 0, len(outValuesSlice))
		for _, val := range outValuesSlice {
			n, _ := strconv.ParseUint(val.(string), 10, 64)
			outValues = append(outValues, n)
		}

		inGeneratorsSlice := v["inGenerators"].([]interface{})
		inGenerators := make([][]byte, 0, len(inGeneratorsSlice))
		for _, val := range inGeneratorsSlice {
			inGenerators = append(inGenerators, h2b(val.(string)))
		}

		outGeneratorsSlice := v["outGenerators"].([]interface{})
		outGenerators := make([][]byte, 0, len(outGeneratorsSlice))
		for _, val := range outGeneratorsSlice {
			outGenerators = append(outGenerators, h2b(val.(string)))
		}

		inFactorsSlice := v["inFactors"].([]interface{})
		inFactors := make([][]byte, 0, len(inFactorsSlice))
		for _, val := range inFactorsSlice {
			inFactors = append(inFactors, h2b(val.(string)))
		}

		outFactorsSlice := v["outFactors"].([]interface{})
		outFactors := make([][]byte, 0, len(outFactorsSlice))
		for _, val := range outFactorsSlice {
			outFactors = append(outFactors, h2b(val.(string)))
		}

		args := FinalValueBlindingFactorArgs{
			InValues:      inValues,
			OutValues:     outValues,
			InGenerators:  inGenerators,
			OutGenerators: outGenerators,
			InFactors:     inFactors,
			OutFactors:    outFactors,
		}

		factor, err := FinalValueBlindingFactor(args)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expectedFactor := v["expected"].(string)
		assert.Equal(t, expectedFactor, hex.EncodeToString(factor[:]))
	}
}

func TestAssetCommitment(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["assetCommitment"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		asset := h2b(v["asset"].(string))
		factor := h2b(v["factor"].(string))

		commitment, err := AssetCommitment(asset, factor)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expected := v["expected"].(string)
		assert.Equal(t, expected, hex.EncodeToString(commitment[:]))
	}
}

func TestValueCommitment(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["valueCommitment"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		value, _ := strconv.ParseUint(v["value"].(string), 10, 64)
		factor := h2b(v["factor"].(string))
		generator := h2b(v["generator"].(string))

		valueCommitment, err := ValueCommitment(value, generator, factor)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expected := v["expected"].(string)
		assert.Equal(t, expected, hex.EncodeToString(valueCommitment[:]))
	}
}

func TestRangeProof(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["rangeProof"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		value, _ := strconv.ParseUint(v["value"].(string), 10, 64)
		blindingPubkey := h2b(v["blindingPubkey"].(string))
		scriptPubkey := h2b(v["scriptPubkey"].(string))
		asset := h2b(v["asset"].(string))
		assetBlindingFactor := h2b(v["assetBlindingFactor"].(string))
		ephemeralPrivkey := h2b(v["ephemeralPrivkey"].(string))
		valueCommitment := h2b(v["valueCommitment"].(string))

		var valueBlindingFactor32 [32]byte
		copy(valueBlindingFactor32[:], h2b(v["valueBlindingFactor"].(string)))

		nonce, err := NonceHash(blindingPubkey, ephemeralPrivkey)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		args := RangeProofArgs{
			Value:               value,
			Nonce:               nonce,
			Asset:               asset,
			AssetBlindingFactor: assetBlindingFactor,
			ValueBlindFactor:    valueBlindingFactor32,
			ValueCommit:         valueCommitment,
			ScriptPubkey:        scriptPubkey,
			Exp:                 0,
			MinBits:             36,
		}

		proof, err := RangeProof(args)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		expectedStr := v["expected"].(string)
		assert.Equal(t, expectedStr, hex.EncodeToString(proof[:]))
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

		seed := h2b(v["seed"].(string))
		outputAsset := h2b(v["outputAsset"].(string))
		outputAssetBlindingFactor := h2b(v["outputAssetBlindingFactor"].(string))
		inputAssetsSlice := v["inputAssets"].([]interface{})
		inputAssets := make([][]byte, 0, len(inputAssetsSlice))
		for _, val := range inputAssetsSlice {
			inputAssets = append(inputAssets, h2b(val.(string)))
		}
		inputAssetBlindingFactorsSlice := v["inputAssetBlindingFactors"].([]interface{})
		inputAssetBlindingFactors := make([][]byte, 0, len(inputAssetBlindingFactorsSlice))
		for _, val := range inputAssetBlindingFactorsSlice {
			inputAssetBlindingFactors = append(inputAssetBlindingFactors, h2b(val.(string)))
		}

		args := SurjectionProofArgs{
			OutputAsset:               outputAsset,
			OutputAssetBlindingFactor: outputAssetBlindingFactor,
			InputAssets:               inputAssets,
			InputAssetBlindingFactors: inputAssetBlindingFactors,
			Seed:                      seed,
		}

		factor, ok := SurjectionProof(args)
		assert.Equal(t, true, ok)

		expectedFactor := v["expected"].(string)
		assert.Equal(t, expectedFactor, hex.EncodeToString(factor[:]))
	}
}

func TestVerifySurjectionProof(t *testing.T) {
	err := setUp()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	vectors := tests["verifySurjectionProof"].([]interface{})
	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		proof := h2b(v["proof"].(string))
		outputAsset := h2b(v["outputAsset"].(string))
		outputAssetBlindingFactor := h2b(v["outputAssetBlindingFactor"].(string))
		inputAssetsSlice := v["inputAssets"].([]interface{})
		inputAssets := make([][]byte, 0, len(inputAssetsSlice))
		for _, val := range inputAssetsSlice {
			inputAssets = append(inputAssets, h2b(val.(string)))
		}
		inputAssetBlindingFactorsSlice := v["inputAssetBlindingFactors"].([]interface{})
		inputAssetBlindingFactors := make([][]byte, 0, len(inputAssetBlindingFactorsSlice))
		for _, val := range inputAssetBlindingFactorsSlice {
			inputAssetBlindingFactors = append(inputAssetBlindingFactors, h2b(val.(string)))
		}

		args := VerifySurjectionProofArgs{
			OutputAsset:               outputAsset,
			OutputAssetBlindingFactor: outputAssetBlindingFactor,
			InputAssets:               inputAssets,
			InputAssetBlindingFactors: inputAssetBlindingFactors,
			Proof:                     proof,
		}
		isValid := VerifySurjectionProof(args)

		expectedValid := v["expected"].(bool)
		assert.Equal(t, expectedValid, isValid)
	}
}
