package psetv2

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcd/btcec"

	"github.com/vulpemventures/go-elements/transaction"

	"github.com/vulpemventures/go-elements/confidential"
)

var (
	ErrOutputsToBeBlindedNotOwned           = errors.New("outputs that are supposed to be blinded are not owned by blinder")
	ErrOwnerDidntProvidedOutputBlindingData = errors.New("owner didnt provided output blinding data")
	ErrNeedUtxo                             = errors.New("input needs utxo")
	ErrInvalidBlinder                       = errors.New("invalid blinder")
	ErrGenerateSurjectionProof              = errors.New("failed to generate surjection proof, please retry")
)

type randomNumberGenerator func() ([]byte, error)

type psetInputIndex int

type Blinder struct {
	pset                        *Pset
	issuanceBlindingPrivateKeys IssuanceBlindingPrivateKeys
	rng                         randomNumberGenerator

	inputTxOutSecrets map[psetInputIndex]confidential.UnblindOutputResult
}

// BlindingInfo is used to find secrets data that are going to be used for
//blinding corresponding output
type BlindingInfo struct {
	// PsetInputIndex defines which previous output of pset input in going to be unblinded
	PsetInputIndex int
	// PrevOutPrivateBlindingKey is private blinding key of inputs previous output
	PrevOutPrivateBlindingKey []byte
}

// IssuanceBlindingPrivateKeys stores the AssetKey and TokenKey that will be used in the Blinder.
type IssuanceBlindingPrivateKeys struct {
	AssetKey []byte
	TokenKey []byte
}

func NewBlinder(
	pset *Pset,
	prevOutBlindingInfos []BlindingInfo,
	issuanceBlindingPrivateKeys IssuanceBlindingPrivateKeys,
	rng randomNumberGenerator,
) (*Blinder, error) {
	var gen randomNumberGenerator
	if rng == nil {
		gen = generateRandomNumber
	} else {
		gen = rng
	}
	//unblind previous outputs
	inputTxOutSecrets, err := getInputSecrets(pset, prevOutBlindingInfos)
	if err != nil {
		return nil, err
	}

	return &Blinder{
		pset:                        pset,
		inputTxOutSecrets:           inputTxOutSecrets,
		issuanceBlindingPrivateKeys: issuanceBlindingPrivateKeys,
		rng:                         gen,
	}, nil
}

func (b *Blinder) Blind() error {
	toBeOrAlreadyBlinded, numOfBlindedOutputs, ownedOutputsToBeBlindedIndexes := b.blindCheck()

	//if all blinded return
	if numOfBlindedOutputs == toBeOrAlreadyBlinded {
		return nil
	}

	//if not all outputs are blinded but inputs secrets are not provided return error
	if len(ownedOutputsToBeBlindedIndexes) == 0 {
		return ErrOutputsToBeBlindedNotOwned
	}

	inputScalar, inputAssets, inputAssetBlinders, err := b.processInputs()
	if err != nil {
		return err
	}

	//blind outputs
	outputScalar, lastBlinded, err := b.blindOutputs(
		ownedOutputsToBeBlindedIndexes,
		toBeOrAlreadyBlinded,
		numOfBlindedOutputs,
		inputScalar,
		inputAssets,
		inputAssetBlinders,
	)
	if err != nil {
		return err
	}

	if !lastBlinded && outputScalar != nil {
		offset, err := confidential.SubtractScalars(outputScalar, inputScalar)
		if err != nil {
			return err
		}

		b.pset.Global.scalars = append(b.pset.Global.scalars, offset)
	}

	return nil
}

//getInputSecrets un-blinds previous outputs
func getInputSecrets(
	pset *Pset,
	prevOutBlindingInfos []BlindingInfo,
) (map[psetInputIndex]confidential.UnblindOutputResult, error) {
	inputTxOutSecrets := make(map[psetInputIndex]confidential.UnblindOutputResult)
	for _, v := range prevOutBlindingInfos {
		if !pset.OwnerProvidedOutputBlindingInfo(v.PsetInputIndex) {
			return nil, ErrOwnerDidntProvidedOutputBlindingData
		}

		input := pset.Inputs[v.PsetInputIndex]
		var prevout *transaction.TxOutput

		if input.nonWitnessUtxo != nil {
			vout := input.previousOutputIndex
			prevout = input.nonWitnessUtxo.Outputs[int(*vout)]
		} else {
			prevout = pset.Inputs[v.PsetInputIndex].witnessUtxo
		}

		unblindOutRes, err := confidential.UnblindOutputWithKey(prevout, v.PrevOutPrivateBlindingKey)
		if err != nil {
			return nil, err
		}

		inputTxOutSecrets[psetInputIndex(v.PsetInputIndex)] = *unblindOutRes
	}

	return inputTxOutSecrets, nil
}

func (b *Blinder) blindCheck() (int, int, []int) {
	toBeOrAlreadyBlinded := 0 //number of outputs that are to be blinded or that are already blinded
	numOfBlindedOutputs := 0
	ownedOutputsToBeBlindedIndexes := make([]int, 0)
	for i, v := range b.pset.Outputs {
		if v.IsBlinded() {
			numOfBlindedOutputs++
		}
		if v.ToBlind() {
			toBeOrAlreadyBlinded++
			if _, ok := b.inputTxOutSecrets[psetInputIndex(*v.outputBlinderIndex)]; ok {
				ownedOutputsToBeBlindedIndexes = append(ownedOutputsToBeBlindedIndexes, i)
			}
		}
	}

	return toBeOrAlreadyBlinded, numOfBlindedOutputs, ownedOutputsToBeBlindedIndexes
}

//processInputs loops through pset inputs in order to gather input assets, blinders
//and scalar that are to be used for blinding outputs, it also blinds owned issuance is any
func (b *Blinder) processInputs() ([]byte, [][]byte, [][]byte, error) {
	inputScalar := make([]byte, 0)
	inputAssets := make([][]byte, 0)
	inputAssetBlinders := make([][]byte, 0)

	for i, v := range b.pset.Inputs {
		utxo := v.GetUtxo()
		if utxo == nil {
			return nil, nil, nil, ErrNeedUtxo
		}
		asset := utxo.Asset
		inputAssets = append(inputAssets, asset)

		if i <= len(b.inputTxOutSecrets)-1 {
			offset, err := confidential.ComputeAndAddToScalarOffset(
				inputScalar,
				b.inputTxOutSecrets[psetInputIndex(i)].Value,
				b.inputTxOutSecrets[psetInputIndex(i)].AssetBlindingFactor,
				b.inputTxOutSecrets[psetInputIndex(i)].ValueBlindingFactor,
			)
			if err != nil {
				return nil, nil, nil, err
			}
			inputScalar = offset

			inputAssets = append(inputAssets, asset)
			inputAssetBlinders = append(inputAssetBlinders, b.inputTxOutSecrets[psetInputIndex(i)].AssetBlindingFactor)
		} else {
			inputAssets = append(inputAssets, asset)
		}

		offset, issuanceAsset, issuanceToken, issuanceAssetBlindingFactor, issuanceTokenBlindingFactor, err :=
			b.handleIssuance(inputScalar, v)
		if err != nil {
			return nil, nil, nil, err
		}
		inputScalar = offset

		inputAssets = append(inputAssets, issuanceAsset)
		inputAssets = append(inputAssets, issuanceToken)
		inputAssetBlinders = append(inputAssetBlinders, issuanceAssetBlindingFactor)
		inputAssetBlinders = append(inputAssetBlinders, issuanceTokenBlindingFactor)
	}

	return inputScalar, inputAssets, inputAssetBlinders, nil
}

//blindOutputs blinds owned outputs and return output scalar
func (b *Blinder) blindOutputs(
	ownedOutputsToBeBlindedIndexes []int,
	toBeOrAlreadyBlinded int,
	numOfBlindedOutputs int,
	inputScalar []byte,
	inputAssets [][]byte,
	inputAssetBlinders [][]byte,
) ([]byte, bool, error) {
	outputScalar := make([]byte, 0)
	lastOutputToBeBlinded := false
	lastBlinded := false
	for _, v := range ownedOutputsToBeBlindedIndexes {
		output := b.pset.Outputs[v]

		if toBeOrAlreadyBlinded-numOfBlindedOutputs == 1 {
			lastOutputToBeBlinded = true
		}

		valueBlindingFactor, err := b.rng()
		if err != nil {
			return nil, false, err
		}

		assetBlindingFactor, err := b.rng()
		if err != nil {
			return nil, false, err
		}

		offset, err := confidential.ComputeAndAddToScalarOffset(
			outputScalar,
			uint64(*output.outputAmount),
			assetBlindingFactor,
			valueBlindingFactor,
		)
		outputScalar = offset

		if lastOutputToBeBlinded {
			subs, err := confidential.SubtractScalars(outputScalar, inputScalar)
			if err != nil {
				return nil, false, err
			}
			outputScalar = subs

			subs, err = confidential.SubtractScalars(valueBlindingFactor, outputScalar)
			if err != nil {
				return nil, false, err
			}
			valueBlindingFactor = subs

			for _, v := range b.pset.Global.scalars {
				subs, err = confidential.SubtractScalars(valueBlindingFactor, v)
				if err != nil {
					return nil, false, err
				}
				valueBlindingFactor = subs
			}

			if bytes.Equal(valueBlindingFactor, transaction.Zero[:]) {
				return nil, false, ErrInvalidBlinder
			}

			b.pset.Global.scalars = nil

			lastBlinded = true
		}

		assetCommitment, err := confidential.AssetCommitment(
			output.outputAsset,
			assetBlindingFactor,
		)
		if err != nil {
			return nil, false, err
		}

		valueCommitment, err := confidential.ValueCommitment(
			uint64(*output.outputAmount),
			assetCommitment[:],
			valueBlindingFactor,
		)

		var vbf32 [32]byte
		copy(vbf32[:], valueBlindingFactor)

		ephemeralPrivKey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return nil, false, err
		}
		outputNonce := ephemeralPrivKey.PubKey().SerializeCompressed()

		nonce, err := confidential.NonceHash(
			output.outputBlindingPubkey,
			ephemeralPrivKey.Serialize(),
		)
		if err != nil {
			return nil, false, err
		}

		rangeProofArgs := confidential.RangeProofArgs{
			Value:               uint64(*output.outputAmount),
			Nonce:               nonce,
			Asset:               output.outputAsset,
			AssetBlindingFactor: assetBlindingFactor,
			ValueBlindFactor:    vbf32,
			ValueCommit:         valueCommitment[:],
			ScriptPubkey:        []byte{},
			MinValue:            1,
			Exp:                 0,
			MinBits:             52,
		}
		rangeProof, err := confidential.RangeProof(rangeProofArgs)
		if err != nil {
			return nil, false, err
		}

		blindValueProof, err := confidential.CreateBlindValueProof(
			b.rng,
			valueBlindingFactor,
			uint64(*output.outputAmount),
			valueCommitment,
			assetCommitment,
		)
		if err != nil {
			return nil, false, err
		}

		randomSeed, err := b.rng()
		if err != nil {
			return nil, false, err
		}

		surjectionProofArgs := confidential.SurjectionProofArgs{
			OutputAsset:               output.outputAsset,
			OutputAssetBlindingFactor: assetBlindingFactor,
			InputAssets:               inputAssets,
			InputAssetBlindingFactors: inputAssetBlinders,
			Seed:                      randomSeed,
		}

		surjectionProof, ok := confidential.SurjectionProof(surjectionProofArgs)
		if !ok {
			return nil, false, ErrGenerateSurjectionProof
		}

		blindAssetProof, err := confidential.CreateBlindAssetProof(
			output.outputAsset,
			assetCommitment,
			assetBlindingFactor,
		)
		if err != nil {
			return nil, false, err
		}

		output.outputAssetCommitment = assetCommitment
		output.outputValueCommitment = valueCommitment
		output.outputEcdhPubkey = outputNonce
		output.outputValueRangeproof = rangeProof
		output.outputAssetSurjectionProof = surjectionProof
		output.outputBlindValueProof = blindValueProof
		output.outputBlindAssetProof = blindAssetProof

		numOfBlindedOutputs++
	}

	return outputScalar, lastBlinded, nil
}

func (b *Blinder) handleIssuance(
	inputScalar []byte,
	input Input,
) ([]byte, []byte, []byte, []byte, []byte, error) {
	var err error
	var issuanceAsset []byte
	var issuanceToken []byte
	var issuanceAssetBlindingFactor []byte
	var issuanceTokenBlindingFactor []byte

	if isIssuance(input) && !isIssuanceBlinded(input) {
		var entropy []byte

		if isReIssuance(input) {
			entropy = input.issuanceAssetEntropy
		} else {
			issuanceInput := &transaction.TxInput{
				Index: *input.previousOutputIndex,
				Hash:  input.previousTxid,
				Issuance: &transaction.TxIssuance{
					AssetEntropy: input.issuanceAssetEntropy,
				},
			}

			issuance, err := transaction.NewTxIssuanceFromInput(issuanceInput)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			entropy = issuance.TxIssuance.AssetEntropy
		}

		issuance := transaction.NewTxIssuanceFromEntropy(entropy)
		issuanceAsset, err = issuance.GenerateAsset()
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		if input.issuanceBlindingNonce == nil && input.issuanceInflationKeys != nil {
			var tokenFLag uint = 0
			if b.issuanceBlindingPrivateKeys.TokenKey != nil {
				tokenFLag = 1
			}

			issuanceToken, err = issuance.GenerateReissuanceToken(tokenFLag)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
		}

		//blind issuance
		if b.shouldBlindIssuance() {
			//blind issuance asset
			valueCommitment, rangeProof, blindValueProof, abf, offset, err := b.blindIssuanceAsset(
				inputScalar,
				issuanceAsset,
				uint64(*input.issuanceValue),
			)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}

			issuanceAssetBlindingFactor = abf
			inputScalar = offset

			input.issuanceValueCommitment = valueCommitment
			input.issuanceValueRangeproof = rangeProof
			input.issuanceBlindValueProof = blindValueProof

			//blind issuance token
			valueCommitment, rangeProof, blindValueProof, abf, offset, err = b.blindIssuanceAsset(
				inputScalar,
				issuanceToken,
				uint64(*input.issuanceInflationKeys),
			)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}

			issuanceTokenBlindingFactor = abf
			inputScalar = offset

			input.issuanceInflationKeysCommitment = valueCommitment
			input.issuanceKeysRangeproof = rangeProof
			input.issuanceBlindInflationKeysProof = blindValueProof
		}
	}

	return inputScalar, issuanceAsset, issuanceToken, issuanceAssetBlindingFactor, issuanceTokenBlindingFactor, nil
}

func isIssuance(input Input) bool {
	return input.issuanceValue != nil
}

func isIssuanceBlinded(input Input) bool {
	return input.issuanceValueCommitment == nil &&
		len(input.issuanceValueRangeproof) == 0 &&
		len(input.issuanceBlindInflationKeysProof) == 0
}

func isReIssuance(input Input) bool {
	if input.issuanceBlindingNonce != nil {
		return !bytes.Equal(input.issuanceBlindingNonce, transaction.Zero[:])
	}

	return false
}

func (b *Blinder) shouldBlindIssuance() bool {
	return b.issuanceBlindingPrivateKeys.AssetKey != nil &&
		b.issuanceBlindingPrivateKeys.TokenKey != nil
}

func (b *Blinder) blindIssuanceAsset(
	inputScalar []byte,
	asset []byte,
	value uint64,
) ([]byte, []byte, []byte, []byte, []byte, error) {
	vbf, err := b.rng()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	abf := make([]byte, 32)
	assetCommitment, err := confidential.AssetCommitment(asset, abf)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	offset, err := confidential.ComputeAndAddToScalarOffset(inputScalar, value, abf, vbf)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	inputScalar = offset

	valueCommitment, err := confidential.ValueCommitment(
		value,
		assetCommitment[:],
		vbf,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	var vbf32 [32]byte
	copy(vbf32[:], vbf)

	var nonce [32]byte
	copy(nonce[:], b.issuanceBlindingPrivateKeys.AssetKey[:])

	rangeProofArgs := confidential.RangeProofArgs{
		Value:               value,
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
		return nil, nil, nil, nil, nil, err
	}

	blindValueProof, err := confidential.CreateBlindValueProof(
		b.rng,
		vbf,
		value,
		valueCommitment,
		assetCommitment,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return valueCommitment, rangeProof, blindValueProof, abf, offset, nil
}
