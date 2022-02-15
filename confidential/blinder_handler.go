package confidential

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/slip77"
	"github.com/vulpemventures/go-elements/transaction"
)

type RandomNumberGenerator func() ([]byte, error)

type BlinderHandler struct {
	masterBlindingKey *slip77.Slip77
	inBlindingKeys    [][]byte
	rng               RandomNumberGenerator
	extraInputs       []UnblindOutputResult
}

type BlinderHandlerOpts struct {
	Rng         RandomNumberGenerator
	ExtraInputs []UnblindOutputResult
}

func NewBlinderHandlerFromMasterBlindingKey(
	masterBlindingKey []byte, opts *BlinderHandlerOpts,
) (*BlinderHandler, error) {
	masterKey, err := slip77.FromMasterKey(masterBlindingKey)
	if err != nil {
		return nil, err
	}
	rng := generateRandomNumber
	var extraInputs []UnblindOutputResult
	if opts != nil {
		if opts.Rng != nil {
			rng = opts.Rng
		}
		if opts.ExtraInputs != nil {
			extraInputs = opts.ExtraInputs
		}
	}

	return &BlinderHandler{
		masterBlindingKey: masterKey,
		rng:               rng,
		extraInputs:       extraInputs,
	}, nil
}

func NewBlinderHandlerFromBlindingKeys(
	inBlindingKeys [][]byte, opts *BlinderHandlerOpts,
) *BlinderHandler {
	rng := generateRandomNumber
	var extraInputs []UnblindOutputResult
	if opts != nil {
		if opts.Rng != nil {
			rng = opts.Rng
		}
		if opts.ExtraInputs != nil {
			extraInputs = opts.ExtraInputs
		}
	}
	return &BlinderHandler{
		inBlindingKeys: inBlindingKeys,
		rng:            rng,
		extraInputs:    extraInputs,
	}
}

func (h *BlinderHandler) VerifyBlindValueProof(
	value uint64, valueCommitment, assetCommitment, proof []byte,
) bool {
	return VerifyBlindValueProof(value, valueCommitment, assetCommitment, proof)
}

func (h *BlinderHandler) VerifyBlindAssetProof(
	asset, assetCommitment, proof []byte,
) bool {
	return VerifyBlindAssetProof(asset, assetCommitment, proof)
}

func (h *BlinderHandler) ComputeAndAddToScalarOffset(
	scalar []byte, value uint64, assetBlinder, valueBlinder []byte,
) ([]byte, error) {
	return ComputeAndAddToScalarOffset(scalar, value, assetBlinder, valueBlinder)
}

func (h *BlinderHandler) SubtractScalars(a, b []byte) ([]byte, error) {
	return SubtractScalars(a, b)
}

func (h *BlinderHandler) LastValueCommitment(
	value uint64, asset, blinder []byte,
) ([]byte, error) {
	return ValueCommitment(value, asset, blinder)
}

func (h *BlinderHandler) LastBlindValueProof(
	value uint64, valueCommitment, assetCommitment, blinder []byte,
) ([]byte, error) {
	return CreateBlindValueProof(
		h.rng, blinder, value, valueCommitment, assetCommitment,
	)
}

func (h *BlinderHandler) LastValueRangeProof(
	value uint64, asset, assetBlinder, valueCommitment, valueBlinder,
	scriptPubkey, nonce []byte,
) ([]byte, error) {
	var nonce32, valueBlinder32 [32]byte
	copy(nonce32[:], nonce)
	copy(valueBlinder32[:], valueBlinder)
	return RangeProof(RangeProofArgs{
		Value:               value,
		Nonce:               nonce32,
		Asset:               asset,
		AssetBlindingFactor: assetBlinder,
		ValueBlindFactor:    valueBlinder32,
		ValueCommit:         valueCommitment,
		ScriptPubkey:        scriptPubkey,
		MinValue:            1,
		Exp:                 0,
		MinBits:             52,
	})
}

func (h *BlinderHandler) UnblindInputs(
	p *psetv2.Pset, inputIndexes []uint32,
) ([]psetv2.OwnedInput, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, err
	}
	for i, in := range p.Inputs {
		if in.GetUtxo() == nil {
			return nil, fmt.Errorf("input %d is missing prevout", i)
		}
	}
	for _, i := range inputIndexes {
		if int(i) > int(p.Global.InputCount)-1 {
			return nil, psetv2.ErrInputIndexOutOfRange
		}
	}

	if len(inputIndexes) == 0 {
		for i := range p.Inputs {
			inputIndexes = append(inputIndexes, uint32(i))
		}
	}

	revealedInputs := make([]psetv2.OwnedInput, 0)
	for _, i := range inputIndexes {
		in := p.Inputs[i]
		prevout := in.GetUtxo()
		revealedInput, err := h.unblindOutput(prevout)
		if err != nil {
			return nil, fmt.Errorf("input %d: %s", i, err)
		}
		revealedInput.Index = i
		revealedInputs = append(revealedInputs, *revealedInput)
	}

	return revealedInputs, nil
}

func (h *BlinderHandler) BlindIssuances(
	p *psetv2.Pset, blindingKeysByIndex map[uint32][]byte,
) ([]psetv2.InputIssuanceBlindingArgs, error) {
	for index, key := range blindingKeysByIndex {
		if int(index) < int(p.Global.InputCount)-1 {
			return nil, psetv2.ErrInputIndexOutOfRange
		}
		if !p.Inputs[index].HasIssuance() {
			return nil, fmt.Errorf(
				"input %d does not have any issuance to blind", index,
			)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf(
				"invalid blinding private key for issuance of input %d", index,
			)
		}
	}

	blindingArgs := make([]psetv2.InputIssuanceBlindingArgs, 0)
	for i, key := range blindingKeysByIndex {
		in := p.Inputs[i]
		asset := in.GetIssuanceAssetHash()

		var err error
		var token, valueCommitment, tokenCommitment, valueRangeProof,
			tokenRangeProof, valueBlindProof, tokenBlindProof, valueBlinder,
			tokenBlinder []byte
		if in.IssuanceValue > 0 {
			valueBlinder, err = h.rng()
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate value blinder for issuance of input %d: %s",
					i, err,
				)
			}
			assetCommitment, err := AssetCommitment(asset, Zero)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate asset commitment for issuance of input %d: %s",
					i, err,
				)
			}
			valueCommitment, err = ValueCommitment(
				in.IssuanceValue, assetCommitment, valueBlinder,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate asset commitment for issuance of input %d: %s",
					i, err,
				)
			}

			valueBlindProof, err = CreateBlindValueProof(
				h.rng, valueBlinder, in.IssuanceValue, valueCommitment,
				assetCommitment,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate blind value proof for issuance of input %d: %s",
					i, err,
				)
			}

			var valueBlinder32, nonce32 [32]byte
			copy(nonce32[:], key)
			copy(valueBlinder32[:], valueBlinder)
			valueRangeProof, err = RangeProof(RangeProofArgs{
				Value:               in.IssuanceValue,
				Nonce:               nonce32,
				Asset:               asset,
				AssetBlindingFactor: Zero,
				ValueBlindFactor:    valueBlinder32,
				ValueCommit:         valueCommitment,
				ScriptPubkey:        make([]byte, 0),
				MinValue:            1,
				Exp:                 0,
				MinBits:             52,
			})
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate value range proof for issuance of input %d: %s",
					i, err,
				)
			}
		}

		if in.IssuanceInflationKeys > 0 {
			token = in.GetIssuanceInflationKeysHash(true)
			tokenBlinder, err = h.rng()
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate value blinder for issuance of input %d: %s",
					i, err,
				)
			}
			assetCommitment, err := AssetCommitment(token, Zero)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate asset commitment for issuance of input %d: %s",
					i, err,
				)
			}
			tokenCommitment, err = ValueCommitment(
				in.IssuanceInflationKeys, assetCommitment, tokenBlinder,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate asset commitment for issuance of input %d: %s",
					i, err,
				)
			}

			tokenBlindProof, err = CreateBlindValueProof(
				h.rng, tokenBlinder, in.IssuanceInflationKeys, tokenCommitment,
				assetCommitment,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate blind value proof for issuance of input %d: %s",
					i, err,
				)
			}

			var tokenBlinder32, nonce32 [32]byte
			copy(nonce32[:], key)
			copy(tokenBlinder32[:], tokenBlinder)
			tokenRangeProof, err = RangeProof(RangeProofArgs{
				Value:               in.IssuanceInflationKeys,
				Nonce:               nonce32,
				Asset:               token,
				AssetBlindingFactor: Zero,
				ValueBlindFactor:    tokenBlinder32,
				ValueCommit:         tokenCommitment,
				ScriptPubkey:        make([]byte, 0),
				MinValue:            1,
				Exp:                 0,
				MinBits:             52,
			})
			if err != nil {
				return nil, fmt.Errorf(
					"failed to generate value range proof for issuance of input %d: %s",
					i, err,
				)
			}
		}

		blindingArgs = append(blindingArgs, psetv2.InputIssuanceBlindingArgs{
			Index:                   i,
			IssuanceAsset:           asset,
			IssuanceToken:           token,
			IssuanceValueCommitment: valueCommitment,
			IssuanceTokenCommitment: tokenCommitment,
			IssuanceValueRangeProof: valueRangeProof,
			IssuanceTokenRangeProof: tokenRangeProof,
			IssuanceValueBlindProof: valueBlindProof,
			IssuanceTokenBlindProof: tokenBlindProof,
			IssuanceValueBlinder:    valueBlinder,
			IssuanceTokenBlinder:    tokenBlinder,
		})
	}

	return blindingArgs, nil
}

func (h *BlinderHandler) BlindOutputs(
	p *psetv2.Pset, outputIndexes []uint32,
	inIssuances []psetv2.InputIssuanceBlindingArgs,
) ([]psetv2.OutputBlindingArgs, error) {
	for _, i := range outputIndexes {
		if int(i) > int(p.Global.OutputCount)-1 {
			return nil, psetv2.ErrOutputIndexOutOfRange
		}
	}
	if outputIndexes == nil {
		for i, out := range p.Outputs {
			if out.IsBlinded() {
				outputIndexes = append(outputIndexes, uint32(i))
			}
		}
	}

	maybeUnblindedIns := h.tryUnblindInputs(p.Inputs)
	inputAssets, inputAssetBlinders := maybeUnblindedIns.assetsAndBlinders()
	for _, i := range inIssuances {
		inputAssets = append(inputAssets, i.IssuanceAsset)
		inputAssetBlinders = append(inputAssetBlinders, Zero)
		if len(i.IssuanceToken) > 0 {
			inputAssets = append(inputAssets, i.IssuanceToken)
			inputAssetBlinders = append(inputAssetBlinders, Zero)
		}
	}

	blindedOutputs := make([]psetv2.OutputBlindingArgs, 0)
	for _, i := range outputIndexes {
		out := p.Outputs[i]
		assetBlinder, err := h.rng()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate asset blinder for output %d: %s", i, err,
			)
		}
		valueBlinder, err := h.rng()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate value blinder for output %d: %s", i, err,
			)
		}
		seed, err := h.rng()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate random seed for output %d: %s", i, err,
			)
		}

		assetCommitment, err := AssetCommitment(out.Asset, assetBlinder)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate asset commitment for output %d: %s", i, err,
			)
		}

		valueCommitment, err := ValueCommitment(
			out.Value, assetCommitment, valueBlinder,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate value commitment for output %d: %s", i, err,
			)
		}

		ephemeralPrivKey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate ephemeral key for ecdh nonce for output %d: %s",
				i, err,
			)
		}
		outputNonce := ephemeralPrivKey.PubKey()
		nonce, err := NonceHash(out.BlindingPubkey, ephemeralPrivKey.Serialize())
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate ecdh nonce for output %d: %s", i, err,
			)
		}

		var valueBlinder32 [32]byte
		copy(valueBlinder32[:], valueBlinder)
		rangeProof, err := RangeProof(RangeProofArgs{
			Value:               out.Value,
			Nonce:               nonce,
			Asset:               out.Asset,
			AssetBlindingFactor: assetBlinder,
			ValueBlindFactor:    valueBlinder32,
			ValueCommit:         valueCommitment,
			ScriptPubkey:        out.Script,
			MinValue:            1,
			Exp:                 0,
			MinBits:             52,
		})
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate value range proof for output %d: %s", i, err,
			)
		}

		surjectionProof, ok := SurjectionProof(SurjectionProofArgs{
			OutputAsset:               out.Asset,
			OutputAssetBlindingFactor: assetBlinder,
			InputAssets:               inputAssets,
			InputAssetBlindingFactors: inputAssetBlinders,
			Seed:                      seed,
		})
		if !ok {
			return nil, fmt.Errorf(
				"failed to generate asset surjection proof for output %d", i,
			)
		}

		valueBlindProof, err := CreateBlindValueProof(
			h.rng, valueBlinder, out.Value, valueCommitment, assetCommitment,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate blind value proof for output %d: %s", i, err,
			)
		}

		assetBlindProof, err := CreateBlindAssetProof(
			out.Asset, assetCommitment, assetBlinder,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate blind asset proof for output %d: %s", i, err,
			)
		}

		blindedOutputs = append(blindedOutputs, psetv2.OutputBlindingArgs{
			Index:                i,
			Nonce:                outputNonce.SerializeCompressed(),
			ValueCommitment:      valueCommitment,
			AssetCommitment:      assetCommitment,
			ValueRangeProof:      rangeProof,
			AssetSurjectionProof: surjectionProof,
			ValueBlindProof:      valueBlindProof,
			AssetBlindProof:      assetBlindProof,
			ValueBlinder:         valueBlinder,
			AssetBlinder:         assetBlinder,
		})
	}

	return blindedOutputs, nil
}

func (h *BlinderHandler) unblindOutput(
	out *transaction.TxOutput,
) (*psetv2.OwnedInput, error) {
	if !out.IsConfidential() {
		value, _ := elementsutil.ValueFromBytes(out.Value)
		asset := elementsutil.AssetHashFromBytes(out.Asset)
		return &psetv2.OwnedInput{
			Value:        value,
			Asset:        asset,
			ValueBlinder: Zero,
			AssetBlinder: Zero,
		}, nil
	}

	blindingkeys := h.inBlindingKeys
	if h.masterBlindingKey != nil {
		blindingPrvkey, _, _ := h.masterBlindingKey.DeriveKey(out.Script)
		blindingkeys = [][]byte{blindingPrvkey.Serialize()}
	}

	for _, key := range blindingkeys {
		revealed, err := UnblindOutputWithKey(out, key)
		if err != nil {
			continue
		}
		return &psetv2.OwnedInput{
			Value:        revealed.Value,
			Asset:        hex.EncodeToString(elementsutil.ReverseBytes(revealed.Asset)),
			ValueBlinder: revealed.ValueBlindingFactor,
			AssetBlinder: revealed.AssetBlindingFactor,
		}, nil
	}
	return nil, fmt.Errorf(
		"failed to unblind output with any key of the provided set of blinding " +
			"keys",
	)
}

type unblindedOuts []UnblindOutputResult

func (outs unblindedOuts) assetsAndBlinders() ([][]byte, [][]byte) {
	assets := make([][]byte, 0, len(outs))
	assetBlinders := make([][]byte, 0, len(outs))
	for _, o := range outs {
		assets = append(assets, o.Asset)
		assetBlinders = append(assetBlinders, o.AssetBlindingFactor)
	}
	return assets, assetBlinders
}

func (h *BlinderHandler) tryUnblindInputs(ins []psetv2.Input) unblindedOuts {
	unblindedOuts := make(unblindedOuts, 0, len(ins))
	for _, in := range ins {
		prevout := in.GetUtxo()
		unblindedOut := UnblindOutputResult{
			Asset:               prevout.Asset,
			AssetBlindingFactor: Zero,
		}

		blindingkeys := h.inBlindingKeys
		if h.masterBlindingKey != nil {
			blindingPrvkey, _, _ := h.masterBlindingKey.DeriveKey(prevout.Script)
			blindingkeys = [][]byte{blindingPrvkey.Serialize()}
		}

		for _, key := range blindingkeys {
			revealed, _ := UnblindOutputWithKey(prevout, key)
			if revealed == nil {
				continue
			}
			unblindedOut = *revealed
			break
		}
		unblindedOuts = append(unblindedOuts, unblindedOut)
	}
	unblindedOuts = append(unblindedOuts, h.extraInputs...)
	return unblindedOuts
}

func generateRandomNumber() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
