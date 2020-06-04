package pset

import (
	"crypto/rand"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/transaction"
	"github.com/vulpemventures/go-secp256k1-zkp"
)

type blinder struct {
	pset             *Pset
	blindingPrivkeys [][]byte
	blindingPubkeys  [][]byte
}

// NewBlinder returns a new instance of blinder, if the passed Pset struct is
// in a valid form, else an error.
func NewBlinder(pset *Pset, blindingPrivkeys, blindingPubkeys [][]byte) (
	*blinder,
	error,
) {
	if err := pset.SanityCheck(); err != nil {
		return nil, err
	}

	return &blinder{
		pset:             pset,
		blindingPrivkeys: blindingPrivkeys,
		blindingPubkeys:  blindingPubkeys,
	}, nil
}

//BlindOutputs method blinds pset's output
func (b *blinder) BlindOutputs() error {
	err := b.validate()
	if err != nil {
		return err
	}

	unblindOutputs, err := b.unblindInputs()
	if err != nil {
		return err
	}

	outputValues := make([]uint64, 0)
	for _, output := range b.pset.UnsignedTx.Outputs {
		var val [9]byte
		copy(val[:], output.Value)
		value, err := confidential.ElementsToSatoshiValue(val)
		if err != nil {
			return err
		}
		outputValues = append(outputValues, value)
	}

	inputAbfs := make([][]byte, 0)
	for _, v := range unblindOutputs {
		inputAbfs = append(inputAbfs, v.AssetBlindingFactor)
	}

	inputVbfs := make([][]byte, 0)
	for _, v := range unblindOutputs {
		inputVbfs = append(inputVbfs, v.ValueBlindingFactor)
	}

	inputAgs := make([][]byte, 0)
	for _, v := range unblindOutputs {
		inputAgs = append(inputAgs, v.Asset)
	}

	inputValues := make([]uint64, 0)
	for _, v := range unblindOutputs {
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

	err = b.blindOutputs(
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

func (b *blinder) validate() error {
	for _, input := range b.pset.Inputs {
		if input.NonWitnessUtxo == nil && input.WitnessUtxo == nil {
			return errors.New("all inputs must contain a non witness " +
				"utxo or a witness utxo")
		}

		if len(input.PartialSigs) > 0 {
			return errors.New("non of the inputs can't be partiali signed")
		}
	}

	if len(b.blindingPrivkeys) != len(b.pset.Inputs) {
		return errors.New("blinding private keys do not match the number" +
			" of inputs")
	}

	if len(b.blindingPubkeys) != (len(b.pset.Outputs) - 1) {
		return errors.New("blinding public keys do not match the number " +
			"of outputs (fee excluded)")
	}
	return nil
}

func (b *blinder) unblindInputs() ([]confidential.UnblindOutputResult, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)
	unblindOutputs := make([]confidential.UnblindOutputResult, 0)
	for index, input := range b.pset.UnsignedTx.Inputs {
		var prevout *transaction.TxOutput
		if b.pset.Inputs[input.Index].NonWitnessUtxo != nil {
			prevout = b.pset.Inputs[input.Index].NonWitnessUtxo.Outputs[input.Index]
		} else {
			prevout = b.pset.Inputs[input.Index].WitnessUtxo
		}

		if len(prevout.RangeProof) > 0 && len(prevout.SurjectionProof) > 0 {
			//TODO: implement CommitmentFromBytes, check comment:
			//https://github.com/vulpemventures/go-elements/pull/79#discussion_r435315406
			commitmentValue, err := secp256k1.CommitmentParse(ctx, prevout.Value)
			if err != nil {
				return nil, err
			}
			unblindInput := confidential.UnblindInput{
				EphemeralPubkey: prevout.Nonce,
				BlindingPrivkey: b.blindingPrivkeys[index],
				Rangeproof:      prevout.RangeProof,
				ValueCommit:     *commitmentValue,
				Asset:           prevout.Asset,
				ScriptPubkey:    prevout.Script,
			}

			output, err := confidential.UnblindOutput(unblindInput)
			if err != nil {
				return nil, err
			}
			unblindOutputs = append(unblindOutputs, *output)
		} else {
			val := [9]byte{}
			copy(val[:], prevout.Value)
			satoshiValue, err := confidential.ElementsToSatoshiValue(val)
			if err != nil {
				return nil, err
			}
			output := confidential.UnblindOutputResult{
				Value:               satoshiValue,
				Asset:               prevout.Asset,
				ValueBlindingFactor: make([]byte, 32),
				AssetBlindingFactor: make([]byte, 32),
			}
			unblindOutputs = append(unblindOutputs, output)
		}
	}
	return unblindOutputs, nil
}

func (b *blinder) generateOutputBlindingFactors(
	inputValues []uint64,
	outputValues []uint64,
	inputAbfs [][]byte,
	inputVbfs [][]byte,
) ([][]byte, [][]byte, error) {
	numOutputs := len(b.pset.Outputs) - 1
	outputAbfs := make([][]byte, 0)
	for i := 0; i < numOutputs; i++ {
		rand, err := generateRandomNumber(32)
		if err != nil {
			return nil, nil, err
		}
		outputAbfs = append(outputAbfs, rand)
	}

	outputVbfs := make([][]byte, 0)
	for i := 0; i < numOutputs-1; i++ {
		rand, err := generateRandomNumber(32)
		if err != nil {
			return nil, nil, err
		}
		outputVbfs = append(outputVbfs, rand)
	}

	input := confidential.FinalValueBlindingFactorInput{
		InValues:      inputValues,
		OutValues:     outputValues,
		InGenerators:  inputAbfs,
		OutGenerators: outputAbfs,
		InFactors:     inputVbfs,
		OutFactors:    outputVbfs,
	}

	finalVbf, err := confidential.FinalValueBlindingFactor(input)
	if err != nil {
		return nil, nil, err
	}
	outputVbfs = append(outputVbfs, finalVbf[:])

	return outputVbfs, outputAbfs, nil
}

func (b *blinder) blindOutputs(
	outputValues []uint64,
	outputAbfs [][]byte,
	outputVbfs [][]byte,
	inputAgs [][]byte,
	inputAbfs [][]byte,
) error {
	for outputIndex, _ := range b.pset.Outputs {
		outputAsset := b.pset.UnsignedTx.Outputs[outputIndex].Asset[1:]
		outputScript := b.pset.UnsignedTx.Outputs[outputIndex].Script
		outputValue := outputValues[outputIndex]
		if len(outputScript) == 0 {
			continue
		}

		randomSeed, err := generateRandomNumber(32)
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

		outVbf := [32]byte{}
		copy(outVbf[:], outputVbfs[outputIndex])

		rangeProofInput := confidential.RangeProofInput{
			Value:               outputValue,
			BlindingPubkey:      b.blindingPubkeys[outputIndex],
			EphemeralPrivkey:    ephemeralPrivKey.Serialize(),
			Asset:               outputAsset,
			AssetBlindingFactor: outputAbfs[outputIndex],
			ValueBlindFactor:    outVbf,
			ValueCommit:         valueCommitment[:],
			ScriptPubkey:        outputScript,
			MinValue:            1,
			Exp:                 0,
			MinBits:             52,
		}
		rangeProof, err := confidential.RangeProof(rangeProofInput)
		if err != nil {
			return err
		}

		surjectionProofInput := confidential.SurjectionProofInput{
			OutputAsset:               outputAsset,
			OutputAssetBlindingFactor: outputAbfs[outputIndex],
			InputAssets:               inputAgs,
			InputAssetBlindingFactors: inputAbfs,
			Seed:                      randomSeed,
		}
		surjectionProof, err := confidential.SurjectionProof(
			surjectionProofInput,
		)
		if err != nil {
			return err
		}

		b.pset.UnsignedTx.Outputs[outputIndex].Asset = assetCommitment[:]
		b.pset.UnsignedTx.Outputs[outputIndex].Value = valueCommitment[:]
		b.pset.UnsignedTx.Outputs[outputIndex].Nonce = outputNonce.SerializeCompressed()
		b.pset.UnsignedTx.Outputs[outputIndex].RangeProof = rangeProof
		b.pset.UnsignedTx.Outputs[outputIndex].SurjectionProof = surjectionProof
	}
	return nil
}

func generateRandomNumber(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
