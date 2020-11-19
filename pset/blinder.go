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
)

type randomNumberGenerator func() ([]byte, error)

// blinder is designed to blind ALL the outputs of the partial transaction.
type blinder struct {
	pset                        *Pset
	blindingPrivkeys            [][]byte
	blindingPubkeys             [][]byte
	issuanceBlindingPrivateKeys []IssuanceBlindingPrivateKeys
	rng                         randomNumberGenerator
}

// IssuanceBlindingPrivateKeys stores the AssetKey and TokenKey that will be used in the Blinder.
type IssuanceBlindingPrivateKeys struct {
	AssetKey []byte
	TokenKey []byte
}

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
	inBlindKeys, outBlindKeys [][]byte,
	inIssuanceBlindKeys []IssuanceBlindingPrivateKeys,
) bool {
	return verifyBlinding(pset, inBlindKeys, outBlindKeys, inIssuanceBlindKeys)
}

// NewBlinder returns a new instance of blinder, if the passed Pset struct is
// in a valid form, else an error.
func NewBlinder(
	pset *Pset,
	blindingPrivkeys,
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

	return &blinder{
		pset:                        pset,
		blindingPrivkeys:            blindingPrivkeys,
		blindingPubkeys:             blindingPubkeys,
		issuanceBlindingPrivateKeys: issuanceBlindingPrivateKeys,
		rng:                         gen,
	}, nil
}

// Blind method blinds the outputs of the partial transaction and also the
// inputs' issuances if any issuanceBlindingPrivateKeys has been provided
func (b *blinder) Blind() error {
	err := b.validate()
	if err != nil {
		return err
	}

	unblindedPrevOuts, unblindedPseudoIns, err := b.unblindInputs()
	if err != nil {
		return err
	}

	totalUnblinded := append(unblindedPrevOuts, unblindedPseudoIns...)
	err = b.blindOutputs(totalUnblinded)
	if err != nil {
		return err
	}

	return b.blindInputs(unblindedPseudoIns)
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

	if len(b.blindingPrivkeys) != len(b.pset.Inputs) {
		return errors.New(
			"blinding private keys do not match the number of inputs",
		)
	}

	if len(b.blindingPubkeys) != len(b.pset.Outputs) {
		return errors.New(
			"blinding public keys do not match the number of outputs. Note that " +
				"fee and outputs that are not meant to be blinded should be added " +
				"after blinder.Blind()",
		)
	}

	return nil
}

// unblindInputs uses the blinding keys provdided to the blinder for unblinding
// the inputs of the partial transaction (if any confidential) and returns also
// the pseudo asset/token inputs for thos inputs containing an issuance
func (b *blinder) unblindInputs() (
	unblindedPrevOuts []confidential.UnblindOutputResult,
	unblindedPseudoIns []confidential.UnblindOutputResult,
	err error,
) {
	// Unblind all inputs
	for index, input := range b.pset.UnsignedTx.Inputs {
		var prevout *transaction.TxOutput
		if b.pset.Inputs[index].NonWitnessUtxo != nil {
			prevout = b.pset.Inputs[index].NonWitnessUtxo.Outputs[input.Index]
		} else {
			prevout = b.pset.Inputs[index].WitnessUtxo
		}

		// if the input is confidential, unnblid it and push the unblided prevout
		// to the unblindedPrevOuts list, otherwise push to just add the unblided
		// unblinded input with 0-value blinding factors
		if prevout.IsConfidential() {
			output, err := confidential.UnblindOutputWithKey(prevout, b.blindingPrivkeys[index])
			if err != nil {
				return nil, nil, err
			}
			unblindedPrevOuts = append(unblindedPrevOuts, *output)
		} else {
			satoshiValue, err := elementsutil.ElementsToSatoshiValue(prevout.Value)
			if err != nil {
				return nil, nil, err
			}

			output := confidential.UnblindOutputResult{
				Value:               satoshiValue,
				Asset:               prevout.Asset[1:],
				ValueBlindingFactor: make([]byte, 32),
				AssetBlindingFactor: make([]byte, 32),
			}
			unblindedPrevOuts = append(unblindedPrevOuts, output)
		}

		// if the current input contains an issuance, add the pseudo input to the
		// returned unblindedPseudoIns array
		if input.HasAnyIssuance() {
			issuance, err := transaction.NewTxIssuanceFromInput(input)
			if err != nil {
				return nil, nil, err
			}

			asset, err := issuance.GenerateAsset()
			if err != nil {
				return nil, nil, err
			}

			value, _ := elementsutil.ElementsToSatoshiValue(input.Issuance.AssetAmount)

			// prepare the random asset and value blinding factors in case the
			// issuance needs to be blinded, otherwise they're set to the 0 byte array
			vbf := make([]byte, 32)
			abf := make([]byte, 32)
			if b.issuanceBlindingPrivateKeys != nil && len(b.issuanceBlindingPrivateKeys) > 0 {
				vbf, err = b.rng()
				if err != nil {
					return nil, nil, err
				}
			}

			output := confidential.UnblindOutputResult{
				Value:               value,
				Asset:               asset,
				ValueBlindingFactor: vbf,
				AssetBlindingFactor: abf,
			}
			unblindedPseudoIns = append(unblindedPseudoIns, output)

			// if the token amount is not defined, it is set to 0x00, thus we need
			// to check if the input.Issuance.TokenAmount, that is encoded in the
			// elements format, contains more than one byte. We simply ignore the
			// token amount for reissuances.
			if i := input.Issuance; !i.IsReissuance() && i.HasTokenAmount() {
				value, err := elementsutil.ElementsToSatoshiValue(i.TokenAmount)
				if err != nil {
					return nil, nil, err
				}

				var tokenFlag uint
				if b.issuanceBlindingPrivateKeys != nil && len(b.issuanceBlindingPrivateKeys) > 0 {
					tokenFlag = 1
				} else {
					tokenFlag = 0
				}

				token, err := issuance.GenerateReissuanceToken(tokenFlag)
				if err != nil {
					return nil, nil, err
				}

				vbf := make([]byte, 32)
				abf := make([]byte, 32)
				if b.issuanceBlindingPrivateKeys != nil && len(b.issuanceBlindingPrivateKeys) > 0 {
					vbf, err = b.rng()
					if err != nil {
						return nil, nil, err
					}
				}

				output := confidential.UnblindOutputResult{
					Value:               value,
					Asset:               token,
					ValueBlindingFactor: vbf,
					AssetBlindingFactor: abf,
				}
				unblindedPseudoIns = append(unblindedPseudoIns, output)
			}
		}
	}
	return
}

func (b *blinder) blindOutputs(
	unblinded []confidential.UnblindOutputResult,
) error {
	outputValues := make([]uint64, 0)
	for _, output := range b.pset.UnsignedTx.Outputs {
		if len(output.Script) > 0 {
			value, err := elementsutil.ElementsToSatoshiValue(output.Value)
			if err != nil {
				return err
			}
			outputValues = append(outputValues, value)
		}
	}

	inputAbfs := make([][]byte, 0)
	for _, v := range unblinded {
		inputAbfs = append(inputAbfs, v.AssetBlindingFactor)
	}

	inputVbfs := make([][]byte, 0)
	for _, v := range unblinded {
		inputVbfs = append(inputVbfs, v.ValueBlindingFactor)
	}

	inputAgs := make([][]byte, 0)
	for _, v := range unblinded {
		inputAgs = append(inputAgs, v.Asset)
	}

	inputValues := make([]uint64, 0)
	for _, v := range unblinded {
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

func (b *blinder) blindInputs(unblinded []confidential.UnblindOutputResult) error {
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
// for every output of the transaction, excluded the fee output that does not
// need to be blinded at all
func (b *blinder) generateOutputBlindingFactors(
	inputValues []uint64,
	outputValues []uint64,
	inputAbfs [][]byte,
	inputVbfs [][]byte,
) ([][]byte, [][]byte, error) {
	numOutputs := len(b.pset.Outputs)
	outputAbfs := make([][]byte, 0)
	for i := 0; i < numOutputs; i++ {
		rand, err := b.rng()
		if err != nil {
			return nil, nil, err
		}
		outputAbfs = append(outputAbfs, rand)
	}

	outputVbfs := make([][]byte, 0)
	for i := 0; i < numOutputs-1; i++ {
		rand, err := b.rng()
		if err != nil {
			return nil, nil, err
		}
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
	assetCommitments := make([][]byte, 0, len(b.pset.Outputs))
	valueCommitments := make([][]byte, 0, len(b.pset.Outputs))
	nonceCommitments := make([][]byte, 0, len(b.pset.Outputs))
	rangeProofs := make([][]byte, 0, len(b.pset.Outputs))
	surjectionProofs := make([][]byte, 0, len(b.pset.Outputs))

	for outputIndex, out := range b.pset.UnsignedTx.Outputs {
		outputAsset := out.Asset[1:]
		outputScript := out.Script
		if len(outputScript) == 0 {
			continue
		}
		outputValue := outputValues[outputIndex]

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
			outputAbfs[outputIndex],
		)
		if err != nil {
			return err
		}

		valueCommitment, err := confidential.ValueCommitment(
			outputValue,
			assetCommitment[:],
			outputVbfs[outputIndex],
		)
		if err != nil {
			return err
		}

		outVbf := [32]byte{}
		copy(outVbf[:], outputVbfs[outputIndex])

		nonce, err := confidential.NonceHash(
			b.blindingPubkeys[outputIndex],
			ephemeralPrivKey.Serialize(),
		)
		if err != nil {
			return err
		}

		rangeProofArgs := confidential.RangeProofArgs{
			Value:               outputValue,
			Nonce:               nonce,
			Asset:               outputAsset,
			AssetBlindingFactor: outputAbfs[outputIndex],
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
			OutputAssetBlindingFactor: outputAbfs[outputIndex],
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
	inBlindKeys, outBlindKeys [][]byte,
	inIssuanceKeys []IssuanceBlindingPrivateKeys,
) bool {
	if len(pset.Inputs) != len(inBlindKeys) {
		return false
	}

	outCount := 0
	for _, out := range pset.UnsignedTx.Outputs {
		if out.IsConfidential() {
			outCount++
		}
	}
	if len(outBlindKeys) != outCount {
		return false
	}

	inAssets := make([][]byte, 0, len(pset.Inputs))
	inIssuanceAssets := make([][]byte, 0)
	inAssetBlinders := make([][]byte, 0, len(pset.Inputs))
	inIssuanceAssetBlinders := make([][]byte, 0)
	for i, in := range pset.Inputs {
		var prevout *transaction.TxOutput
		if in.WitnessUtxo != nil {
			prevout = in.WitnessUtxo
		} else {
			prevIndex := pset.UnsignedTx.Inputs[i].Index
			prevout = in.NonWitnessUtxo.Outputs[prevIndex]
		}

		unblinded, err := confidential.UnblindOutputWithKey(prevout, inBlindKeys[i])
		if err != nil {
			return false
		}
		if unblinded == nil {
			inAssets = append(inAssets, prevout.Asset[1:])
			inAssetBlinders = append(inAssetBlinders, make([]byte, 32))
		} else {
			inAssets = append(inAssets, unblinded.Asset)
			inAssetBlinders = append(inAssetBlinders, unblinded.AssetBlindingFactor)
		}

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
	for i, out := range pset.UnsignedTx.Outputs {
		if out.IsConfidential() {
			unblinded, err := confidential.UnblindOutputWithKey(out, outBlindKeys[i])
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
