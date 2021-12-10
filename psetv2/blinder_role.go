package psetv2

import (
	"bytes"
	"errors"

	"github.com/vulpemventures/go-elements/elementsutil"

	"github.com/btcsuite/btcd/btcec"

	"github.com/vulpemventures/go-elements/transaction"
)

var (
	ErrOutputsToBeBlindedNotOwned           = errors.New("outputs that are supposed to be blinded are not owned by blinder")
	ErrOwnerDidntProvidedOutputBlindingData = errors.New("owner didnt provided output blinding data")
	ErrNeedUtxo                             = errors.New("input needs utxo")
	ErrInvalidBlinder                       = errors.New("invalid blinder")
	ErrGenerateSurjectionProof              = errors.New("failed to generate surjection proof, please retry")
)

type Blinder interface {
	AssetCommitment(asset, factor []byte) ([]byte, error)
	ValueCommitment(value uint64, generator, factor []byte) ([]byte, error)
	NonceHash(pubKey, privKey []byte) ([32]byte, error)
	RangeProof(value uint64,
		nonce [32]byte,
		asset []byte,
		assetBlindingFactor []byte,
		valueBlindFactor [32]byte,
		valueCommit []byte,
		scriptPubkey []byte,
		minValue uint64,
		exp int,
		minBits int,
	) ([]byte, error)
	SurjectionProof(
		outputAsset []byte,
		outputAssetBlindingFactor []byte,
		inputAssets [][]byte,
		inputAssetBlindingFactors [][]byte,
		seed []byte,
		numberOfTargets int,
	) ([]byte, bool)
	VerifySurjectionProof(
		inputAssets [][]byte,
		inputAssetBlindingFactors [][]byte,
		outputAsset []byte,
		outputAssetBlindingFactor []byte,
		proof []byte,
	) bool
	SubtractScalars(a []byte, b []byte) ([]byte, error)
	ComputeAndAddToScalarOffset(
		scalar []byte,
		value uint64,
		assetBlinder []byte,
		valueBlinder []byte,
	) ([]byte, error)
	CreateBlindValueProof(
		rng func() ([]byte, error),
		valueBlindingFactor []byte,
		amount uint64,
		valueCommitment []byte,
		assetCommitment []byte,
	) ([]byte, error)
	CreateBlindAssetProof(
		asset []byte,
		assetCommitment []byte,
		assetBlinder []byte,
	) ([]byte, error)
	VerifyBlindValueProof(
		value int64,
		valueCommitment []byte,
		blindValueProof []byte,
		assetCommitment []byte,
	) (bool, error)
	VerifyBlindAssetProof(
		asset []byte,
		blindAssetProof []byte,
		assetCommitment []byte,
	) (bool, error)
	UnblindOutputWithKey(
		out *transaction.TxOutput,
		blindKey []byte,
	) (uint64, []byte, []byte, []byte, error)
}

type BlinderRole struct {
	pset                        *Pset
	blinderSvc                  Blinder
	issuanceBlindingPrivateKeys IssuanceBlindingPrivateKeys
	rng                         randomNumberGenerator
	inputTxOutSecrets           map[psetInputIndex]InputSecrets
}

// NewBlinderRole provides methods to Blind pset and to verify it blinding was correct
//blinderSvc is used in order to decouple from confidential pkg
//prevOutBlindingInfos is used to find secrets data that are going to be used for blinding corresponding output
//issuanceBlindingPrivateKeys is used to blind asset and token if it is issuance transaction
//rng allows used to pass custom random number generator function
func NewBlinderRole(
	pset *Pset,
	blinderSvc Blinder,
	prevOutBlindingInfos []UnBlindingInfo,
	issuanceBlindingPrivateKeys IssuanceBlindingPrivateKeys,
	rng randomNumberGenerator,
) (*BlinderRole, error) {
	var gen randomNumberGenerator
	if rng == nil {
		gen = generateRandomNumber
	} else {
		gen = rng
	}

	//unblind previous outputs
	inputTxOutSecrets, err := getInputSecrets(pset, prevOutBlindingInfos, blinderSvc)
	if err != nil {
		return nil, err
	}

	return &BlinderRole{
		pset:                        pset,
		blinderSvc:                  blinderSvc,
		issuanceBlindingPrivateKeys: issuanceBlindingPrivateKeys,
		rng:                         gen,
		inputTxOutSecrets:           inputTxOutSecrets,
	}, nil
}

func (b *BlinderRole) Blind() error {
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
		offset, err := b.blinderSvc.SubtractScalars(outputScalar, inputScalar)
		if err != nil {
			return err
		}

		b.pset.Global.scalars = append(b.pset.Global.scalars, offset)
	}

	return nil
}

func (b *BlinderRole) Verify(outUnBlindingInfos []UnBlindingInfo) bool {
	if len(b.pset.Inputs) != len(b.inputTxOutSecrets) {
		return false
	}

	outCount := 0
	for _, out := range b.pset.Outputs {
		if out.IsBlinded() {
			outCount++
		}
	}
	if len(outUnBlindingInfos) != outCount {
		return false
	}

	inAssets := make([][]byte, 0, len(b.pset.Inputs))
	inIssuanceAssets := make([][]byte, 0)
	inAssetBlinders := make([][]byte, 0, len(b.pset.Inputs))
	inIssuanceAssetBlinders := make([][]byte, 0)
	for i, inputBlindData := range b.inputTxOutSecrets {
		inAssets = append(inAssets, inputBlindData.Asset)
		inAssetBlinders = append(inAssetBlinders, inputBlindData.AssetBlindingFactor)

		if input := b.pset.Inputs[i]; input.isIssuance() {
			if input.isIssuanceBlinded() {
				issuanceUnBlindingKeys := [][]byte{
					b.issuanceBlindingPrivateKeys.AssetKey,
					b.issuanceBlindingPrivateKeys.TokenKey,
				}
				unblinded, err := b.unblindIssuance(input, issuanceUnBlindingKeys)
				if err != nil {
					return false
				}
				inIssuanceAssets = append(inIssuanceAssets, unblinded.Asset.Asset)
				inIssuanceAssetBlinders = append(
					inIssuanceAssetBlinders,
					unblinded.Asset.AssetBlindingFactor,
				)

				if input.issuanceInflationKeys != nil {
					inIssuanceAssets = append(inIssuanceAssets, unblinded.Token.Asset)
					inIssuanceAssetBlinders = append(
						inIssuanceAssetBlinders,
						unblinded.Token.AssetBlindingFactor,
					)
				}
			} else {
				iss, err := transaction.NewTxIssuanceFromInput(&transaction.TxInput{
					Hash:  input.previousTxid,
					Index: *input.previousOutputIndex,
					Issuance: &transaction.TxIssuance{
						AssetEntropy: input.issuanceAssetEntropy,
					},
				})
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

				if input.issuanceInflationKeys != nil {
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
	for _, v := range outUnBlindingInfos {
		out := b.pset.Outputs[v.OutIndex]
		amount, err := elementsutil.SatoshiToElementsValue(uint64(*out.outputAmount))
		if err != nil {
			return false
		}
		if out.IsBlinded() {
			_, asset, _, abf, err := b.blinderSvc.UnblindOutputWithKey(
				&transaction.TxOutput{
					Asset:           out.outputAsset,
					Value:           amount,
					Script:          out.outputScript,
					Nonce:           out.outputEcdhPubkey,
					RangeProof:      out.outputValueRangeproof,
					SurjectionProof: out.outputAssetSurjectionProof,
				},
				v.OutPrivateBlindingKey,
			)
			if err != nil {
				return false
			}
			if !b.blinderSvc.VerifySurjectionProof(
				inAssets,
				inAssetBlinders,
				asset,
				abf,
				out.outputAssetSurjectionProof,
			) {
				return false
			}
		}
	}

	return true
}

type randomNumberGenerator func() ([]byte, error)

type psetInputIndex int

// UnBlindingInfo holds data necessary for unblinding outputs
type UnBlindingInfo struct {
	// OutIndex defines which previous output of pset input in going to be unblinded
	OutIndex int
	// OutPrivateBlindingKey is private blinding key of inputs previous output
	OutPrivateBlindingKey []byte
}

// IssuanceBlindingPrivateKeys stores the AssetKey and TokenKey that will be used in the BlinderRole.
type IssuanceBlindingPrivateKeys struct {
	AssetKey []byte
	TokenKey []byte
}

// InputSecrets is the type returned by the functions that unblind tx
// outs. It contains the unblinded asset and value and also the respective
// blinding factors.
type InputSecrets struct {
	Value               uint64
	Asset               []byte
	ValueBlindingFactor []byte
	AssetBlindingFactor []byte
}

//getInputSecrets un-blinds previous outputs
func getInputSecrets(
	pset *Pset,
	prevOutBlindingInfos []UnBlindingInfo,
	blinderSvc Blinder,
) (map[psetInputIndex]InputSecrets, error) {
	inputTxOutSecrets := make(map[psetInputIndex]InputSecrets)
	for _, v := range prevOutBlindingInfos {
		if !pset.OwnerProvidedOutputBlindingInfo(v.OutIndex) {
			return nil, ErrOwnerDidntProvidedOutputBlindingData
		}

		input := pset.Inputs[v.OutIndex]
		var prevout *transaction.TxOutput

		if input.nonWitnessUtxo != nil {
			vout := input.previousOutputIndex
			prevout = input.nonWitnessUtxo.Outputs[int(*vout)]
		} else {
			prevout = pset.Inputs[v.OutIndex].witnessUtxo
		}

		value, asset, vbf, abf, err := blinderSvc.UnblindOutputWithKey(
			prevout,
			v.OutPrivateBlindingKey,
		)
		if err != nil {
			return nil, err
		}

		inputTxOutSecrets[psetInputIndex(v.OutIndex)] = InputSecrets{
			Value:               value,
			Asset:               asset,
			ValueBlindingFactor: vbf,
			AssetBlindingFactor: abf,
		}
	}

	return inputTxOutSecrets, nil
}

func (b *BlinderRole) blindCheck() (int, int, []int) {
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
func (b *BlinderRole) processInputs() ([]byte, [][]byte, [][]byte, error) {
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
			offset, err := b.blinderSvc.ComputeAndAddToScalarOffset(
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
func (b *BlinderRole) blindOutputs(
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

		offset, err := b.blinderSvc.ComputeAndAddToScalarOffset(
			outputScalar,
			uint64(*output.outputAmount),
			assetBlindingFactor,
			valueBlindingFactor,
		)
		outputScalar = offset

		if lastOutputToBeBlinded {
			subs, err := b.blinderSvc.SubtractScalars(outputScalar, inputScalar)
			if err != nil {
				return nil, false, err
			}
			outputScalar = subs

			subs, err = b.blinderSvc.SubtractScalars(valueBlindingFactor, outputScalar)
			if err != nil {
				return nil, false, err
			}
			valueBlindingFactor = subs

			for _, v := range b.pset.Global.scalars {
				subs, err = b.blinderSvc.SubtractScalars(valueBlindingFactor, v)
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

		assetCommitment, err := b.blinderSvc.AssetCommitment(
			output.outputAsset,
			assetBlindingFactor,
		)
		if err != nil {
			return nil, false, err
		}

		valueCommitment, err := b.blinderSvc.ValueCommitment(
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

		nonce, err := b.blinderSvc.NonceHash(
			output.outputBlindingPubkey,
			ephemeralPrivKey.Serialize(),
		)
		if err != nil {
			return nil, false, err
		}

		rangeProof, err := b.blinderSvc.RangeProof(
			uint64(*output.outputAmount),
			nonce,
			output.outputAsset,
			assetBlindingFactor,
			vbf32,
			valueCommitment[:],
			[]byte{},
			1,
			0,
			52,
		)
		if err != nil {
			return nil, false, err
		}

		blindValueProof, err := b.blinderSvc.CreateBlindValueProof(
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

		surjectionProof, ok := b.blinderSvc.SurjectionProof(
			output.outputAsset,
			assetBlindingFactor,
			inputAssets,
			inputAssetBlinders,
			randomSeed,
			0,
		)
		if !ok {
			return nil, false, ErrGenerateSurjectionProof
		}

		blindAssetProof, err := b.blinderSvc.CreateBlindAssetProof(
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

func (b *BlinderRole) handleIssuance(
	inputScalar []byte,
	input Input,
) ([]byte, []byte, []byte, []byte, []byte, error) {
	var err error
	var issuanceAsset []byte
	var issuanceToken []byte
	var issuanceAssetBlindingFactor []byte
	var issuanceTokenBlindingFactor []byte

	if input.isIssuance() && !input.isIssuanceBlinded() {
		var entropy []byte

		if input.isReIssuance() {
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

func (b *BlinderRole) shouldBlindIssuance() bool {
	return b.issuanceBlindingPrivateKeys.AssetKey != nil &&
		b.issuanceBlindingPrivateKeys.TokenKey != nil
}

func (b *BlinderRole) blindIssuanceAsset(
	inputScalar []byte,
	asset []byte,
	value uint64,
) ([]byte, []byte, []byte, []byte, []byte, error) {
	vbf, err := b.rng()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	abf := make([]byte, 32)
	assetCommitment, err := b.blinderSvc.AssetCommitment(asset, abf)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	offset, err := b.blinderSvc.ComputeAndAddToScalarOffset(inputScalar, value, abf, vbf)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	inputScalar = offset

	valueCommitment, err := b.blinderSvc.ValueCommitment(
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

	rangeProof, err := b.blinderSvc.RangeProof(
		value,
		nonce,
		asset,
		abf,
		vbf32,
		valueCommitment[:],
		[]byte{},
		1,
		0,
		52,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	blindValueProof, err := b.blinderSvc.CreateBlindValueProof(
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

type UnblindIssuanceResult struct {
	Asset *InputSecrets
	Token *InputSecrets
}

func (b *BlinderRole) unblindIssuance(
	in Input,
	blindKeys [][]byte,
) (*UnblindIssuanceResult, error) {
	if len(blindKeys) <= 1 {
		return nil, errors.New("missing asset blind private key")
	}
	if !in.isIssuance() {
		return nil, errors.New("missing input issuance")
	}
	if !in.isIssuanceBlinded() {
		return nil, errors.New("missing asset range proof")
	}

	if in.issuanceInflationKeys != nil {
		if len(in.issuanceBlindInflationKeysProof) <= 0 {
			return nil, errors.New("missing token range proof")
		}
		if len(blindKeys) < 1 {
			return nil, errors.New("missing token blind private key")
		}
	}

	asset, err := calcAssetHash(in)
	if err != nil {
		return nil, err
	}

	amount, err := elementsutil.SatoshiToElementsValue(uint64(*in.issuanceValue))
	if err != nil {
		return nil, err
	}
	outs := []*transaction.TxOutput{
		{
			Asset:      asset,
			Value:      amount,
			RangeProof: in.issuanceValueRangeproof,
			Script:     make([]byte, 0),
		},
	}
	if in.issuanceInflationKeys != nil {
		token, err := calcTokenHash(in)
		if err != nil {
			return nil, err
		}

		amount, err := elementsutil.SatoshiToElementsValue(uint64(*in.issuanceInflationKeys))
		if err != nil {
			return nil, err
		}

		outs = append(outs, &transaction.TxOutput{
			Asset:      token,
			Value:      amount,
			RangeProof: in.issuanceKeysRangeproof,
			Script:     make([]byte, 0),
		})
	}

	res := &UnblindIssuanceResult{}
	for i, out := range outs {
		v, a, _, _, err := b.blinderSvc.UnblindOutputWithKey(out, blindKeys[i])
		if err != nil {
			return nil, err
		}
		//TODO check bellow
		if i == 0 {
			res.Asset.Asset = a
			res.Asset.Value = v
			res.Asset.AssetBlindingFactor = make([]byte, 32)
		} else {
			res.Token.Asset = a
			res.Token.Value = v
			res.Token.AssetBlindingFactor = make([]byte, 32)
		}
	}
	return res, nil
}

func calcAssetHash(in Input) ([]byte, error) {
	iss, err := transaction.NewTxIssuanceFromInput(&transaction.TxInput{
		Hash:  in.previousTxid,
		Index: *in.previousOutputIndex,
		Issuance: &transaction.TxIssuance{
			AssetEntropy: in.issuanceAssetEntropy,
		},
	})
	if err != nil {
		return nil, err
	}

	return iss.GenerateAsset()
}

func calcTokenHash(in Input) ([]byte, error) {
	iss, err := transaction.NewTxIssuanceFromInput(&transaction.TxInput{
		Hash:  in.previousTxid,
		Index: *in.previousOutputIndex,
		Issuance: &transaction.TxIssuance{
			AssetEntropy: in.issuanceAssetEntropy,
		},
	})
	if err != nil {
		return nil, err
	}

	return iss.GenerateReissuanceToken(1)
}
