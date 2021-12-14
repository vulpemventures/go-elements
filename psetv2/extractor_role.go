package psetv2

import (
	"bytes"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

type ExtractorRole struct {
	pset       *Pset
	blinderSvc Blinder
}

func NewExtractorRole(pset *Pset, blinderSvc Blinder) *ExtractorRole {
	return &ExtractorRole{
		pset:       pset,
		blinderSvc: blinderSvc,
	}
}

func (e *ExtractorRole) Extract() (*transaction.Transaction, error) {
	tx := transaction.NewTx(int32(*e.pset.Global.version))

	if e.pset.CalculateTimeLock() != nil {
		tx.Locktime = *e.pset.CalculateTimeLock()
	}

	for _, v := range e.pset.Inputs {
		txInput := &transaction.TxInput{}
		txInput.Hash = v.previousTxid
		txInput.Index = *v.previousOutputIndex
		txInput.Sequence = *v.sequence
		if txInput.Issuance != nil {
			txInput.Issuance.AssetBlindingNonce = v.issuanceBlindingNonce
			txInput.Issuance.AssetEntropy = v.issuanceAssetEntropy
			if v.issuanceValue != nil {
				issuanceValue, err := elementsutil.SatoshiToElementsValue(uint64(*v.issuanceValue))
				if err != nil {
					return nil, err
				}
				txInput.Issuance.AssetAmount = issuanceValue
			}
			if v.issuanceValueCommitment != nil {
				txInput.Issuance.AssetAmount = v.issuanceValueCommitment
				txInput.IssuanceRangeProof = v.issuanceValueRangeproof
			}

			if v.issuanceInflationKeys != nil {
				tokenValue, err := elementsutil.SatoshiToElementsValue(uint64(*v.issuanceInflationKeys))
				if err != nil {
					return nil, err
				}
				txInput.Issuance.TokenAmount = tokenValue
			}
			if v.issuanceInflationKeysCommitment != nil {
				txInput.Issuance.TokenAmount = v.issuanceInflationKeysCommitment
				txInput.InflationRangeProof = v.issuanceInflationKeysCommitment
			}
		}
		txInput.IsPegin = v.peginWitness != nil
		if txInput.IsPegin {
			txInput.PeginWitness = [][]byte{v.peginWitness}
		}

		if v.finalScriptSig != nil {
			txInput.Script = v.finalScriptSig
		}

		if v.finalScriptWitness != nil {
			// In order to set the witness, need to re-deserialize
			// the field as encoded within the PSET packet.  For
			// each input, the witness is encoded as a stack with
			// one or more items.
			witnessReader := bytes.NewReader(
				v.finalScriptWitness,
			)

			// First we extract the number of witness elements
			// encoded in the above witnessReader.
			witCount, err := wire.ReadVarInt(witnessReader, 0)
			if err != nil {
				return nil, err
			}

			// Now that we know how may inputs we'll need, we'll
			// construct a packing slice, then read out each input
			// (with a varint prefix) from the witnessReader.
			txInput.Witness = make(transaction.TxWitness, witCount)
			for j := uint64(0); j < witCount; j++ {
				wit, err := wire.ReadVarBytes(
					witnessReader, 0, txscript.MaxScriptSize, "witness",
				)
				if err != nil {
					return nil, err
				}
				txInput.Witness[j] = wit
			}
		}

		tx.AddInput(txInput)
	}

	for _, v := range e.pset.Outputs {
		txOutput := &transaction.TxOutput{}
		txOutput.Script = v.outputScript

		expValue := v.outputValueCommitment == nil
		expValue = expValue && v.outputAmount != nil
		if v.outputValueCommitment != nil && v.outputAmount != nil {
			expValue = expValue && v.outputBlindValueProof != nil
			expValue = expValue && v.outputAssetCommitment != nil
			valid, err := e.blinderSvc.VerifyBlindValueProof(
				*v.outputAmount,
				v.outputValueCommitment,
				v.outputBlindValueProof,
				v.outputAssetCommitment,
			)
			if err != nil {
				return nil, err
			}
			expValue = expValue && valid
		}
		if expValue {
			value, err := elementsutil.SatoshiToElementsValue(uint64(*v.outputAmount))
			if err != nil {
				return nil, err
			}
			txOutput.Value = value
		} else {
			txOutput.Value = v.outputValueCommitment
			txOutput.RangeProof = v.outputValueRangeproof
		}

		expAsset := v.outputAssetCommitment == nil
		expAsset = expAsset && v.outputAsset != nil
		if v.outputAssetCommitment != nil && v.outputAsset != nil {
			expAsset = expAsset && v.outputBlindAssetProof != nil
			expAsset = expAsset && v.outputAsset != nil
			valid, err := e.blinderSvc.VerifyBlindAssetProof(
				v.outputAsset[1:],
				v.outputBlindAssetProof,
				v.outputAssetCommitment,
			)
			if err != nil {
				return nil, err
			}
			expAsset = expAsset && valid
		}
		if expAsset {
			txOutput.Asset = v.outputAsset
		} else {
			txOutput.Asset = v.outputAssetCommitment
			txOutput.SurjectionProof = v.outputAssetSurjectionProof
		}

		txOutput.Nonce = v.outputEcdhPubkey

		tx.AddOutput(txOutput)
	}

	return tx, nil
}
