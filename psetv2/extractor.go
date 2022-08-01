package psetv2

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

var (
	ErrExtractorForbiddenExtraction = fmt.Errorf(
		"pset must be complete to extract final transaction",
	)
)

func Extract(p *Pset) (*transaction.Transaction, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid pset: %s", err)
	}

	if !p.IsComplete() {
		return nil, ErrExtractorForbiddenExtraction
	}
	tx := transaction.NewTx(int32(p.Global.TxVersion))
	tx.Locktime = p.Locktime()

	for _, in := range p.Inputs {
		txIn := &transaction.TxInput{
			Hash:     in.PreviousTxid,
			Index:    in.PreviousTxIndex,
			Sequence: in.Sequence,
		}

		var issuance *transaction.TxIssuance
		if in.IssuanceValue > 0 || in.IssuanceValueCommitment != nil {
			value := in.IssuanceValueCommitment
			if value == nil {
				value, _ = elementsutil.ValueToBytes(in.IssuanceValue)
			}
			tokenValue := in.IssuanceInflationKeysCommitment
			if tokenValue == nil {
				tokenValue = []byte{0x00}
				if in.IssuanceInflationKeys > 0 {
					tokenValue, _ = elementsutil.ValueToBytes(in.IssuanceInflationKeys)
				}
			}
			issuance = &transaction.TxIssuance{
				AssetBlindingNonce: in.IssuanceBlindingNonce,
				AssetEntropy:       in.IssuanceAssetEntropy,
				AssetAmount:        value,
				TokenAmount:        tokenValue,
			}
		}
		txIn.Issuance = issuance
		if in.IssuanceValueRangeproof != nil {
			txIn.IssuanceRangeProof = in.IssuanceValueRangeproof
		}
		if in.IssuanceInflationKeysRangeproof != nil {
			txIn.InflationRangeProof = in.IssuanceInflationKeysRangeproof
		}

		txIn.IsPegin = in.PeginWitness != nil
		if txIn.IsPegin {
			txIn.PeginWitness = in.PeginWitness
		}

		if in.FinalScriptSig != nil {
			txIn.Script = in.FinalScriptSig
		}

		if in.FinalScriptWitness != nil {
			// In order to set the witness, need to re-deserialize
			// the field as encoded within the PSET packet.  For
			// each input, the witness is encoded as a stack with
			// one or more items.
			witnessReader := bytes.NewReader(
				in.FinalScriptWitness,
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
			txIn.Witness = make(transaction.TxWitness, witCount)
			for j := uint64(0); j < witCount; j++ {
				wit, err := wire.ReadVarBytes(
					witnessReader, 0, txscript.MaxScriptSize, "witness",
				)
				if err != nil {
					return nil, err
				}
				txIn.Witness[j] = wit
			}
		}

		tx.AddInput(txIn)
	}

	for _, out := range p.Outputs {
		txOut := &transaction.TxOutput{
			Script: out.Script,
		}
		value := out.ValueCommitment
		if value == nil {
			value, _ = elementsutil.ValueToBytes(out.Value)
		}
		txOut.Value = value

		asset := out.AssetCommitment
		if asset == nil {
			asset = append([]byte{0x01}, out.Asset...)
		}
		txOut.Asset = asset

		nonce := []byte{0x00}
		if out.EcdhPubkey != nil {
			nonce = out.EcdhPubkey
		}
		txOut.Nonce = nonce

		if out.ValueRangeproof != nil {
			txOut.RangeProof = out.ValueRangeproof
		}

		if out.AssetSurjectionProof != nil {
			txOut.SurjectionProof = out.AssetSurjectionProof
		}

		tx.AddOutput(txOut)
	}

	return tx, nil
}
