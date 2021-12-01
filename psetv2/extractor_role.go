package psetv2

import (
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

type ExtractorRole struct {
	pset       *Pset
	blinderSvc Blinder
}

func NewExtractorRole(pset *Pset) *ExtractorRole {
	return &ExtractorRole{
		pset: pset,
	}
}

func (e *ExtractorRole) Extract() (*transaction.Transaction, error) {
	tx := transaction.NewTx(int32(*e.pset.Global.version))

	tx.Locktime = *e.pset.CalculateTimeLock()

	for _, v := range e.pset.Inputs {
		txInput := &transaction.TxInput{}
		txInput.Hash = v.previousTxid
		txInput.Index = *v.previousOutputIndex
		txInput.Sequence = *v.sequence
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

		txInput.IsPegin = v.peginWitness != nil
		txInput.PeginWitness = [][]byte{v.peginWitness}

		txInput.Witness = [][]byte{v.finalScriptSig, v.finalScriptWitness}

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
				v.outputAsset,
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
