package pset

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

var (
	// ErrGenerateSurjectionProof is returned if the computation of the
	// surjection proof fails.
	ErrGenerateSurjectionProof = errors.New(
		"failed to generate surjection proof, please retry",
	)
	// ErrNeedPrevout is returned if a BlindingDataLike needs the input's prevout but received nil
	ErrNeedPrevout = errors.New(
		"need prevout to get blinding data",
	)
)

type randomNumberGenerator func() ([]byte, error)

// blinder is designed to blind ALL the outputs of the partial transaction.
type blinder struct {
	pset                        *Pset
	inputsBlindingData          []*confidential.UnblindOutputResult
	outputsIndexToPubKey        map[int][]byte
	issuanceBlindingPrivateKeys []IssuanceBlindingPrivateKeys
	rng                         randomNumberGenerator
}

// BlindingDataLike defines data used to get blinders from input
type BlindingDataLike interface {
	GetUnblindOutputResult(prevout *transaction.TxOutput) (*confidential.UnblindOutputResult, error)
}

// PrivateBlindingKey = a bytes slice | used on confidential input
type PrivateBlindingKey []byte

// BlindingData = blinders
type BlindingData confidential.UnblindOutputResult

// GetUnblindOutputResult for PrivateBlindingKey unblind the associated prevout using the private key
// or return zero value blinders in case of unconfidential input
func (privKey PrivateBlindingKey) GetUnblindOutputResult(prevout *transaction.TxOutput) (*confidential.UnblindOutputResult, error) {
	if prevout == nil {
		return nil, ErrNeedPrevout
	}

	// check if the input is confidential
	if prevout.IsConfidential() {
		return confidential.UnblindOutputWithKey(prevout, privKey)
	}

	// unconf input
	satoshiValue, err := elementsutil.ElementsToSatoshiValue(prevout.Value)
	if err != nil {
		return nil, err
	}

	blindingData := &confidential.UnblindOutputResult{
		Value:               satoshiValue,
		Asset:               prevout.Asset[1:],
		ValueBlindingFactor: make([]byte, 32),
		AssetBlindingFactor: make([]byte, 32),
	}

	return blindingData, nil
}

// GetUnblindOutputResult only cast BlindingData to unblindOutputResult
func (blindingData BlindingData) GetUnblindOutputResult(prevout *transaction.TxOutput) (*confidential.UnblindOutputResult, error) {
	return &confidential.UnblindOutputResult{
		Value:               blindingData.Value,
		Asset:               blindingData.Asset,
		ValueBlindingFactor: blindingData.ValueBlindingFactor,
		AssetBlindingFactor: blindingData.AssetBlindingFactor,
	}, nil
}

// IssuanceBlindingPrivateKeys stores the AssetKey and TokenKey that will be used in the blinder.
type IssuanceBlindingPrivateKeys struct {
	AssetKey []byte
	TokenKey []byte
}

// ToSlice get private keys as []byte from IssuanceBlindingPrivateKeys
func (ik IssuanceBlindingPrivateKeys) ToSlice() [][]byte {
	keys := [][]byte{ik.AssetKey}
	if len(ik.TokenKey) > 0 {
		keys = append(keys, ik.TokenKey)
	}
	return keys
}

// VerifyBlinding verifies the proofs of all the confidential outputs of the
// given transaction, with the given in/out private blinding keys.
func VerifyBlinding(
	pset *Pset,
	blindingDataLikes []BlindingDataLike,
	outBlindKeysByIndex map[int][]byte,
	inIssuanceKeys []IssuanceBlindingPrivateKeys,
) (bool, error) {
	inputsBlindingData, err := blindingDataLikeToUnblindResult(blindingDataLikes, pset)
	if err != nil {
		return false, err
	}

	return verifyBlinding(pset, inputsBlindingData, outBlindKeysByIndex, inIssuanceKeys), nil
}

// NewBlinder returns a new instance of blinder, if the passed Pset struct is
// in a valid form, else an error.
func NewBlinder(
	pset *Pset,
	blindingDataLikes []BlindingDataLike,
	blindingPubkeys [][]byte,
	issuanceBlindingPrivateKeys []IssuanceBlindingPrivateKeys,
	rng randomNumberGenerator,
) (*blinder, error) {
	if err := pset.SanityCheck(); err != nil {
		return nil, err
	}

	var gen randomNumberGenerator
	if rng == nil {
		gen = generateRandomNumber
	} else {
		gen = rng
	}

	outputsPubKeyByIndex := make(map[int][]byte, 0)
	for index, output := range pset.UnsignedTx.Outputs {
		if len(output.Script) > 0 {
			outputsPubKeyByIndex[index] = blindingPubkeys[index]
		}
	}

	inputsBlindingData, err := blindingDataLikeToUnblindResult(blindingDataLikes, pset)
	if err != nil {
		return nil, err
	}

	return &blinder{
		pset:                        pset,
		inputsBlindingData:          inputsBlindingData,
		issuanceBlindingPrivateKeys: issuanceBlindingPrivateKeys,
		outputsIndexToPubKey:        outputsPubKeyByIndex,
		rng:                         gen,
	}, nil
}

func blindingDataLikeToUnblindResult(blindingDataLikes []BlindingDataLike, pset *Pset) ([]*confidential.UnblindOutputResult, error) {
	inputsBlindingData := make([]*confidential.UnblindOutputResult, len(blindingDataLikes), len(blindingDataLikes))
	for index, blindDataLike := range blindingDataLikes {
		input := pset.Inputs[index]
		var prevout *transaction.TxOutput

		if input.NonWitnessUtxo != nil {
			vout := pset.UnsignedTx.Inputs[index].Index
			prevout = input.NonWitnessUtxo.Outputs[vout]
		} else {
			prevout = pset.Inputs[index].WitnessUtxo
		}

		unblindOutRes, err := blindDataLike.GetUnblindOutputResult(prevout)
		if err != nil {
			return nil, err
		}

		inputsBlindingData[index] = unblindOutRes
	}

	return inputsBlindingData, nil
}

// Blind method blinds the outputs of the partial transaction and also the
// inputs' issuances if any issuanceBlindingPrivateKeys has been provided
func (b *blinder) Blind() error {
	err := b.validate()
	if err != nil {
		return err
	}

	issuanceBlindingData, err := b.unblindInputsToIssuanceBlindingData()
	if err != nil {
		return err
	}

	totalUnblinded := append(b.inputsBlindingData, issuanceBlindingData...)
	err = b.blindOutputs(totalUnblinded)
	if err != nil {
		return err
	}

	return b.blindInputs(issuanceBlindingData)
}

// validate checks that the all the required blinder's fields are valid and
// that the partial transaction provided is valid and ready to be blinded
func (b *blinder) validate() error {
	for _, input := range b.pset.Inputs {
		if input.NonWitnessUtxo == nil && input.WitnessUtxo == nil {
			return errors.New(
				"all inputs must contain a non witness utxo or a witness utxo",
			)
		}

		if len(input.PartialSigs) > 0 {
			return errors.New("inputs must not contain signatures")
		}
	}

	if len(b.inputsBlindingData) != len(b.pset.Inputs) {
		return errors.New(
			"inputs blinding data do not match the number of inputs",
		)
	}

	return nil
}

// unblindInputs uses the blinding keys provdided to the blinder for unblinding
// the inputs of the partial transaction (if any confidential) and returns also
// the pseudo asset/token inputs for thos inputs containing an issuance
func (b *blinder) unblindInputsToIssuanceBlindingData() (
	unblindedPseudoIns []*confidential.UnblindOutputResult,
	err error,
) {
	for _, input := range b.pset.UnsignedTx.Inputs {
		// if the current input contains an issuance, add the pseudo input to the
		// returned unblindedPseudoIns array
		if input.HasAnyIssuance() {
			issuance, err := transaction.NewTxIssuanceFromInput(input)
			if err != nil {
				return nil, err
			}

			asset, err := issuance.GenerateAsset()
			if err != nil {
				return nil, err
			}

			value, _ := elementsutil.ElementsToSatoshiValue(input.Issuance.AssetAmount)

			// prepare the random asset and value blinding factors in case the
			// issuance needs to be blinded, otherwise they're set to the 0 byte array
			vbf := make([]byte, 32)
			abf := make([]byte, 32)
			if b.issuanceBlindingPrivateKeys != nil && len(b.issuanceBlindingPrivateKeys) > 0 {
				vbf, err = b.rng()
				if err != nil {
					return nil, err
				}
			}

			output := confidential.UnblindOutputResult{
				Value:               value,
				Asset:               asset,
				ValueBlindingFactor: vbf,
				AssetBlindingFactor: abf,
			}
			unblindedPseudoIns = append(unblindedPseudoIns, &output)

			// if the token amount is not defined, it is set to 0x00, thus we need
			// to check if the input.Issuance.TokenAmount, that is encoded in the
			// elements format, contains more than one byte. We simply ignore the
			// token amount for reissuances.
			if i := input.Issuance; !i.IsReissuance() && i.HasTokenAmount() {
				value, err := elementsutil.ElementsToSatoshiValue(i.TokenAmount)
				if err != nil {
					return nil, err
				}

				var tokenFlag uint
				if b.issuanceBlindingPrivateKeys != nil && len(b.issuanceBlindingPrivateKeys) > 0 {
					tokenFlag = 1
				} else {
					tokenFlag = 0
				}

				token, err := issuance.GenerateReissuanceToken(tokenFlag)
				if err != nil {
					return nil, err
				}

				vbf := make([]byte, 32)
				abf := make([]byte, 32)
				if b.issuanceBlindingPrivateKeys != nil && len(b.issuanceBlindingPrivateKeys) > 0 {
					vbf, err = b.rng()
					if err != nil {
						return nil, err
					}
				}

				output := confidential.UnblindOutputResult{
					Value:               value,
					Asset:               token,
					ValueBlindingFactor: vbf,
					AssetBlindingFactor: abf,
				}
				unblindedPseudoIns = append(unblindedPseudoIns, &output)
			}
		}
	}
	return
}

func (b *blinder) blindOutputs(
	inputsBlindingData []*confidential.UnblindOutputResult,
) error {
	outputValues := make([]uint64, 0)
	for index := range b.outputsIndexToPubKey {
		output := b.pset.UnsignedTx.Outputs[index]
		if len(output.Script) > 0 {
			value, err := elementsutil.ElementsToSatoshiValue(output.Value)
			if err != nil {
				return err
			}
			outputValues = append(outputValues, value)
		}
	}

	inputAbfs := make([][]byte, 0)
	inputVbfs := make([][]byte, 0)
	inputAgs := make([][]byte, 0)
	inputValues := make([]uint64, 0)
	for _, v := range inputsBlindingData {
		inputAbfs = append(inputAbfs, v.AssetBlindingFactor)
		inputVbfs = append(inputVbfs, v.ValueBlindingFactor)
		inputAgs = append(inputAgs, v.Asset)
		inputValues = append(inputValues, v.Value)
	}

	outputVbfs, outputAbfs, err := b.generateOutputBlindingFactors(
		inputValues,
		outputValues,
		inputAbfs,
		inputVbfs,
	)
	if err != nil {
		return err
	}

	err = b.createBlindedOutputs(
		outputValues,
		outputAbfs,
		outputVbfs,
		inputAgs,
		inputAbfs,
	)
	if err != nil {
		return err
	}

	return nil
}

func (b *blinder) blindInputs(unblinded []*confidential.UnblindOutputResult) error {
	// do not blind anything if no blinding keys are provided
	if b.issuanceBlindingPrivateKeys == nil || len(b.issuanceBlindingPrivateKeys) == 0 {
		return nil
	}

	getBlindingFactors := func(asset []byte) ([]byte, []byte, error) {
		for _, u := range unblinded {
			if bytes.Equal(asset, u.Asset) {
				return u.ValueBlindingFactor, u.AssetBlindingFactor, nil
			}
		}
		return nil, nil, errors.New("no blinding factors generated for pseudo issuance inputs")
	}

	for index, input := range b.pset.UnsignedTx.Inputs {
		if input.HasAnyIssuance() {
			issuance, err := transaction.NewTxIssuanceFromInput(input)
			if err != nil {
				return err
			}

			asset, err := issuance.GenerateAsset()
			if err != nil {
				return err
			}

			vbf, abf, err := getBlindingFactors(asset)
			if err != nil {
				return err
			}

			err = b.blindAsset(index, asset, vbf, abf)
			if err != nil {
				return err
			}

			// ONLY in case the issuance is not a reissuance, if the token amount is
			// not defined, it is set to 0x00, thus it's required to check that the
			// input.Issuance.TokenAmount, that's encoded in the elements format (!),
			// is longer than one byte. Reissuances, instead, cannot have a token
			// amount defined.
			if i := input.Issuance; !i.IsReissuance() && i.HasTokenAmount() {
				token, err := issuance.GenerateReissuanceToken(
					ConfidentialReissuanceTokenFlag,
				)
				if err != nil {
					return err
				}

				vbf, abf, err := getBlindingFactors(token)
				if err != nil {
					return err
				}

				err = b.blindToken(index, token, vbf, abf)
				if err != nil {
					return err
				}
			}
		}

	}
	return nil
}

// generateOutputBlindingFactors generates the asset and token blinding factors
// for every output to blind
func (b *blinder) generateOutputBlindingFactors(
	inputValues []uint64,
	outputValues []uint64,
	inputAbfs [][]byte,
	inputVbfs [][]byte,
) ([][]byte, [][]byte, error) {
	rand, err := b.rng()
	if err != nil {
		return nil, nil, err
	}

	numOutputs := len(b.outputsIndexToPubKey)
	outputAbfs := make([][]byte, 0, numOutputs)
	outputVbfs := make([][]byte, 0, numOutputs)

	for i := 0; i < numOutputs; i++ {
		outputAbfs = append(outputAbfs, rand)
	}

	for i := 0; i < numOutputs-1; i++ {
		outputVbfs = append(outputVbfs, rand)
	}

	finalVbfArgs := confidential.FinalValueBlindingFactorArgs{
		InValues:      inputValues,
		OutValues:     outputValues,
		InGenerators:  inputAbfs,
		OutGenerators: outputAbfs,
		InFactors:     inputVbfs,
		OutFactors:    outputVbfs,
	}

	finalVbf, err := confidential.FinalValueBlindingFactor(finalVbfArgs)
	if err != nil {
		return nil, nil, err
	}
	outputVbfs = append(outputVbfs, finalVbf[:])

	return outputVbfs, outputAbfs, nil
}

// createBlindedOutputs generates a blinding nonce, an asset and a value
// commitments, a range and a surjection proof for every output that must
// be blinded, fee out excluded
func (b *blinder) createBlindedOutputs(
	outputValues []uint64,
	outputAbfs [][]byte,
	outputVbfs [][]byte,
	inputAgs [][]byte,
	inputAbfs [][]byte,
) error {
	numOutputsToBlind := len(b.outputsIndexToPubKey)
	assetCommitments := make([][]byte, 0, numOutputsToBlind)
	valueCommitments := make([][]byte, 0, numOutputsToBlind)
	nonceCommitments := make([][]byte, 0, numOutputsToBlind)
	rangeProofs := make([][]byte, 0, numOutputsToBlind)
	surjectionProofs := make([][]byte, 0, numOutputsToBlind)

	indexLoop := 0
	for outputIndex, blindingPublicKey := range b.outputsIndexToPubKey {
		out := b.pset.UnsignedTx.Outputs[outputIndex]
		outputAsset := out.Asset[1:]
		outputScript := out.Script

		if len(outputScript) == 0 {
			continue
		}
		outputValue := outputValues[indexLoop]

		randomSeed, err := b.rng()
		if err != nil {
			return err
		}

		ephemeralPrivKey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return err
		}
		outputNonce := ephemeralPrivKey.PubKey()

		assetCommitment, err := confidential.AssetCommitment(
			outputAsset,
			outputAbfs[indexLoop],
		)
		if err != nil {
			return err
		}

		valueCommitment, err := confidential.ValueCommitment(
			outputValue,
			assetCommitment[:],
			outputVbfs[indexLoop],
		)
		if err != nil {
			return err
		}

		outVbf := [32]byte{}
		copy(outVbf[:], outputVbfs[indexLoop])

		nonce, err := confidential.NonceHash(
			blindingPublicKey,
			ephemeralPrivKey.Serialize(),
		)
		if err != nil {
			return err
		}

		rangeProofArgs := confidential.RangeProofArgs{
			Value:               outputValue,
			Nonce:               nonce,
			Asset:               outputAsset,
			AssetBlindingFactor: outputAbfs[indexLoop],
			ValueBlindFactor:    outVbf,
			ValueCommit:         valueCommitment[:],
			ScriptPubkey:        outputScript,
			MinValue:            1,
			Exp:                 0,
			MinBits:             52,
		}
		rangeProof, err := confidential.RangeProof(rangeProofArgs)
		if err != nil {
			return err
		}

		surjectionProofArgs := confidential.SurjectionProofArgs{
			OutputAsset:               outputAsset,
			OutputAssetBlindingFactor: outputAbfs[indexLoop],
			InputAssets:               inputAgs,
			InputAssetBlindingFactors: inputAbfs,
			Seed:                      randomSeed,
		}

		surjectionProof, ok := confidential.SurjectionProof(surjectionProofArgs)
		if !ok {
			return ErrGenerateSurjectionProof
		}

		assetCommitments = append(assetCommitments, assetCommitment[:])
		valueCommitments = append(valueCommitments, valueCommitment[:])
		nonceCommitments = append(nonceCommitments, outputNonce.SerializeCompressed())
		rangeProofs = append(rangeProofs, rangeProof)
		surjectionProofs = append(surjectionProofs, surjectionProof)

		indexLoop++
	}

	for i, out := range b.pset.UnsignedTx.Outputs {
		out.Asset = assetCommitments[i]
		out.Value = valueCommitments[i]
		out.Nonce = nonceCommitments[i]
		out.RangeProof = rangeProofs[i]
		out.SurjectionProof = surjectionProofs[i]
	}

	return nil
}

func (b *blinder) blindAsset(index int, asset, vbf, abf []byte) error {
	if len(b.issuanceBlindingPrivateKeys) < index || len(b.issuanceBlindingPrivateKeys[index].AssetKey) != 32 {
		return errors.New("missing private blinding key for issuance asset amount")
	}

	assetAmount := b.pset.UnsignedTx.Inputs[index].Issuance.AssetAmount
	assetCommitment, err := confidential.AssetCommitment(asset, abf)
	if err != nil {
		return err
	}

	assetAmountSatoshi, err := elementsutil.ElementsToSatoshiValue(assetAmount)
	if err != nil {
		return err
	}

	valueCommitment, err := confidential.ValueCommitment(
		assetAmountSatoshi,
		assetCommitment[:],
		vbf,
	)
	if err != nil {
		return err
	}

	var vbf32 [32]byte
	copy(vbf32[:], vbf)

	var nonce [32]byte
	copy(nonce[:], b.issuanceBlindingPrivateKeys[index].AssetKey[:])

	rangeProofArgs := confidential.RangeProofArgs{
		Value:               assetAmountSatoshi,
		Nonce:               nonce,
		Asset:               asset,
		AssetBlindingFactor: abf,
		ValueBlindFactor:    vbf32,
		ValueCommit:         valueCommitment[:],
		ScriptPubkey:        []byte{},
		MinValue:            1,
		Exp:                 0,
		MinBits:             52,
	}
	rangeProof, err := confidential.RangeProof(rangeProofArgs)
	if err != nil {
		return err
	}

	b.pset.UnsignedTx.Inputs[index].IssuanceRangeProof = rangeProof
	b.pset.UnsignedTx.Inputs[index].Issuance.AssetAmount = valueCommitment[:]
	return nil
}

func (b *blinder) blindToken(index int, token, vbf, abf []byte) error {
	if len(b.issuanceBlindingPrivateKeys) < index || len(b.issuanceBlindingPrivateKeys[index].TokenKey) != 32 {
		return errors.New("missing private blinding key for issuance token amount")
	}

	tokenAmount := b.pset.UnsignedTx.Inputs[index].Issuance.TokenAmount
	assetCommitment, err := confidential.AssetCommitment(token, abf)
	if err != nil {
		return err
	}

	tokenAmountSatoshi, err := elementsutil.ElementsToSatoshiValue(tokenAmount)
	if err != nil {
		return err
	}

	valueCommitment, err := confidential.ValueCommitment(
		tokenAmountSatoshi,
		assetCommitment[:],
		vbf,
	)
	if err != nil {
		return err
	}

	var vbf32 [32]byte
	copy(vbf32[:], vbf)

	var nonce [32]byte
	copy(nonce[:], b.issuanceBlindingPrivateKeys[index].TokenKey[:])

	rangeProofArgs := confidential.RangeProofArgs{
		Value:               tokenAmountSatoshi,
		Nonce:               nonce,
		Asset:               token,
		AssetBlindingFactor: abf,
		ValueBlindFactor:    vbf32,
		ValueCommit:         valueCommitment[:],
		ScriptPubkey:        []byte{},
		MinValue:            1,
		Exp:                 0,
		MinBits:             52,
	}
	rangeProof, err := confidential.RangeProof(rangeProofArgs)
	if err != nil {
		return err
	}

	b.pset.UnsignedTx.Inputs[index].InflationRangeProof = rangeProof
	b.pset.UnsignedTx.Inputs[index].Issuance.TokenAmount = valueCommitment[:]
	return nil
}

func verifyBlinding(
	pset *Pset,
	inBlindData []*confidential.UnblindOutputResult,
	outPrivBlindKeysByIndex map[int][]byte,
	inIssuanceKeys []IssuanceBlindingPrivateKeys,
) bool {
	if len(pset.Inputs) != len(inBlindData) {
		return false
	}

	outCount := 0
	for _, out := range pset.UnsignedTx.Outputs {
		if out.IsConfidential() {
			outCount++
		}
	}
	if len(outPrivBlindKeysByIndex) != outCount {
		return false
	}

	inAssets := make([][]byte, 0, len(pset.Inputs))
	inIssuanceAssets := make([][]byte, 0)
	inAssetBlinders := make([][]byte, 0, len(pset.Inputs))
	inIssuanceAssetBlinders := make([][]byte, 0)
	for i, inputBlindData := range inBlindData {
		inAssets = append(inAssets, inputBlindData.Asset)
		inAssetBlinders = append(inAssetBlinders, inputBlindData.AssetBlindingFactor)

		if txIn := pset.UnsignedTx.Inputs[i]; txIn.HasAnyIssuance() {
			if txIn.HasConfidentialIssuance() {
				unblinded, err := confidential.UnblindIssuance(txIn, inIssuanceKeys[i].ToSlice())
				if err != nil {
					return false
				}
				inIssuanceAssets = append(inIssuanceAssets, unblinded.Asset.Asset)
				inIssuanceAssetBlinders = append(
					inIssuanceAssetBlinders,
					unblinded.Asset.AssetBlindingFactor,
				)

				if txIn.Issuance.HasTokenAmount() {
					inIssuanceAssets = append(inIssuanceAssets, unblinded.Token.Asset)
					inIssuanceAssetBlinders = append(
						inIssuanceAssetBlinders,
						unblinded.Token.AssetBlindingFactor,
					)
				}
			} else {
				iss, err := transaction.NewTxIssuanceFromInput(txIn)
				if err != nil {
					return false
				}
				asset, err := iss.GenerateAsset()
				if err != nil {
					return false
				}
				inIssuanceAssets = append(inIssuanceAssets, asset)
				inIssuanceAssetBlinders = append(
					inIssuanceAssetBlinders,
					transaction.Zero[:],
				)

				if txIn.Issuance.HasTokenAmount() {
					token, err := iss.GenerateReissuanceToken(0)
					if err != nil {
						return false
					}
					inIssuanceAssets = append(inIssuanceAssets, token)
					inIssuanceAssetBlinders = append(
						inIssuanceAssetBlinders,
						transaction.Zero[:],
					)
				}
			}
		}
	}

	inAssets = append(inAssets, inIssuanceAssets...)
	inAssetBlinders = append(inAssetBlinders, inIssuanceAssetBlinders...)
	for outputIndex, privBlindKey := range outPrivBlindKeysByIndex {
		out := pset.UnsignedTx.Outputs[outputIndex]
		if out.IsConfidential() {
			unblinded, err := confidential.UnblindOutputWithKey(out, privBlindKey)
			if err != nil {
				return false
			}
			args := confidential.VerifySurjectionProofArgs{
				InputAssets:               inAssets,
				InputAssetBlindingFactors: inAssetBlinders,
				OutputAsset:               unblinded.Asset,
				OutputAssetBlindingFactor: unblinded.AssetBlindingFactor,
				Proof:                     out.SurjectionProof,
			}
			if !confidential.VerifySurjectionProof(args) {
				return false
			}
		}
	}

	return true
}

func generateRandomNumber() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
