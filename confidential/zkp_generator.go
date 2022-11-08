package confidential

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/slip77"
	"github.com/vulpemventures/go-elements/transaction"
)

type RandomNumberGenerator func() ([]byte, error)

type zkpGenerator struct {
	masterBlindingKey *slip77.Slip77
	inBlindingKeys    [][]byte
	rng               RandomNumberGenerator
	ownedInputs       map[uint32]psetv2.OwnedInput
}

type ZKPGeneratorOpts struct {
	Rng RandomNumberGenerator
}

func NewZKPGeneratorFromMasterBlindingKey(
	masterBlindingKey []byte, opts *ZKPGeneratorOpts,
) (*zkpGenerator, error) {
	masterKey, err := slip77.FromMasterKey(masterBlindingKey)
	if err != nil {
		return nil, err
	}
	rng := generateRandomNumber
	if opts != nil {
		if opts.Rng != nil {
			rng = opts.Rng
		}
	}

	return &zkpGenerator{
		masterBlindingKey: masterKey,
		rng:               rng,
	}, nil
}

func NewZKPGeneratorFromBlindingKeys(
	inBlindingKeys [][]byte, opts *ZKPGeneratorOpts,
) *zkpGenerator {
	rng := generateRandomNumber
	if opts != nil {
		if opts.Rng != nil {
			rng = opts.Rng
		}
	}
	return &zkpGenerator{
		inBlindingKeys: inBlindingKeys,
		rng:            rng,
	}
}

func NewZKPGeneratorFromOwnedInputs(
	ownedInputs map[uint32]psetv2.OwnedInput, opts *ZKPGeneratorOpts,
) (*zkpGenerator, error) {
	for i, ownedIn := range ownedInputs {
		if i != ownedIn.Index {
			return nil, fmt.Errorf(
				"invalid index key for owned input, got %d expected %d",
				i, ownedIn.Index,
			)
		}

	}

	rng := generateRandomNumber
	if opts != nil {
		if opts.Rng != nil {
			rng = opts.Rng
		}
	}

	return &zkpGenerator{
		ownedInputs: ownedInputs,
		rng:         rng,
	}, nil
}

func (g *zkpGenerator) ComputeAndAddToScalarOffset(
	scalar []byte, value uint64, assetBlinder, valueBlinder []byte,
) ([]byte, error) {
	return ComputeAndAddToScalarOffset(scalar, value, assetBlinder, valueBlinder)
}

func (g *zkpGenerator) SubtractScalars(a, b []byte) ([]byte, error) {
	return SubtractScalars(a, b)
}

func (g *zkpGenerator) LastValueCommitment(
	value uint64, asset, blinder []byte,
) ([]byte, error) {
	return ValueCommitment(value, asset, blinder)
}

func (g *zkpGenerator) LastBlindValueProof(
	value uint64, valueCommitment, assetCommitment, blinder []byte,
) ([]byte, error) {
	return CreateBlindValueProof(
		g.rng, blinder, value, valueCommitment, assetCommitment,
	)
}

func (g *zkpGenerator) LastValueRangeProof(
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
		Exp:                 0,
		MinBits:             52,
	})
}

func (g *zkpGenerator) UnblindInputs(
	p *psetv2.Pset, inputIndexes []uint32,
) ([]psetv2.OwnedInput, error) {
	if err := validatePset(p); err != nil {
		return nil, err
	}
	if err := validateInputIndexes(inputIndexes, p); err != nil {
		return nil, err
	}

	if len(inputIndexes) == 0 {
		for i := range p.Inputs {
			inputIndexes = append(inputIndexes, uint32(i))
		}
	}

	if len(g.ownedInputs) > 0 {
		ownedIns := make([]psetv2.OwnedInput, 0, len(inputIndexes))
		for _, i := range inputIndexes {
			if ownedIn, ok := g.ownedInputs[i]; ok {
				ownedIns = append(ownedIns, ownedIn)
			}
		}
		return ownedIns, nil
	}

	revealedInputs := make([]psetv2.OwnedInput, 0)
	for _, i := range inputIndexes {
		in := p.Inputs[i]
		prevout := in.GetUtxo()
		revealedInput, err := g.unblindOutput(prevout)
		if err != nil {
			return nil, fmt.Errorf("input %d: %s", i, err)
		}
		revealedInput.Index = i
		revealedInputs = append(revealedInputs, *revealedInput)
	}

	return revealedInputs, nil
}

func (g *zkpGenerator) BlindIssuances(
	p *psetv2.Pset, blindingKeysByIndex map[uint32][]byte,
) ([]psetv2.InputIssuanceBlindingArgs, error) {
	if err := validatePset(p); err != nil {
		return nil, err
	}
	if err := validateBlindKeysByIndex(blindingKeysByIndex, p); err != nil {
		return nil, err
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
			valueBlinder, err = g.rng()
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
				g.rng, valueBlinder, in.IssuanceValue, valueCommitment,
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
			token = in.GetIssuanceInflationKeysHash()
			tokenBlinder, err = g.rng()
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
				g.rng, tokenBlinder, in.IssuanceInflationKeys, tokenCommitment,
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

func (g *zkpGenerator) BlindOutputs(
	p *psetv2.Pset, outputIndexes []uint32,
) ([]psetv2.OutputBlindingArgs, error) {
	if err := validatePset(p); err != nil {
		return nil, err
	}
	if err := validateOutputIndexes(outputIndexes, p); err != nil {
		return nil, err
	}

	if outputIndexes == nil {
		for i, out := range p.Outputs {
			if out.NeedsBlinding() {
				outputIndexes = append(outputIndexes, uint32(i))
			}
		}
	}

	maybeUnblindedIns := g.revealInputs(p.Inputs)
	inputAssets, inputAssetBlinders := maybeUnblindedIns.assetsAndBlinders()
	for _, i := range p.Inputs {
		if i.HasIssuance() {
			inputAssets = append(inputAssets, i.GetIssuanceAssetHash())
			inputAssetBlinders = append(inputAssetBlinders, Zero)
			if !i.HasReissuance() {
				inputAssets = append(inputAssets, i.GetIssuanceInflationKeysHash())
				inputAssetBlinders = append(inputAssetBlinders, Zero)
			}
		}
	}

	blindedOutputs := make([]psetv2.OutputBlindingArgs, 0)
	for _, i := range outputIndexes {
		out := p.Outputs[i]
		assetBlinder, err := g.rng()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate asset blinder for output %d: %s", i, err,
			)
		}
		valueBlinder, err := g.rng()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to generate value blinder for output %d: %s", i, err,
			)
		}
		seed, err := g.rng()
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

		ephemeralPrivKey, err := btcec.NewPrivateKey()
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
			g.rng, valueBlinder, out.Value, valueCommitment, assetCommitment,
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
			Nonce:                nonce[:],
			NonceCommitment:      outputNonce.SerializeCompressed(),
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

func (g *zkpGenerator) unblindOutput(
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

	blindingkeys := g.inBlindingKeys
	if g.masterBlindingKey != nil {
		blindingPrvkey, _, _ := g.masterBlindingKey.DeriveKey(out.Script)
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

func (g *zkpGenerator) revealInputs(ins []psetv2.Input) unblindedOuts {
	if len(g.ownedInputs) > 0 {
		return sortUnblindedOuts(ins, g.ownedInputs)
	}
	return g.tryUnblindInputs(ins)
}

func (g *zkpGenerator) tryUnblindInputs(ins []psetv2.Input) unblindedOuts {
	unblindedOuts := make(unblindedOuts, 0, len(ins))
	for _, in := range ins {
		prevout := in.GetUtxo()
		unblindedOut := UnblindOutputResult{
			Asset:               prevout.Asset,
			AssetBlindingFactor: Zero,
		}

		blindingkeys := g.inBlindingKeys
		if g.masterBlindingKey != nil {
			blindingPrvkey, _, _ := g.masterBlindingKey.DeriveKey(prevout.Script)
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

func validatePset(p *psetv2.Pset) error {
	if err := p.SanityCheck(); err != nil {
		return err
	}
	for i, in := range p.Inputs {
		if in.GetUtxo() == nil {
			return fmt.Errorf("input %d is missing prevout", i)
		}
	}
	return nil
}

func validateBlindKeysByIndex(
	blindingKeysByIndex map[uint32][]byte, p *psetv2.Pset,
) error {
	for index, key := range blindingKeysByIndex {
		if int(index) < int(p.Global.InputCount)-1 {
			return psetv2.ErrInputIndexOutOfRange
		}
		if !p.Inputs[index].HasIssuance() {
			return fmt.Errorf(
				"input %d does not have any issuance to blind", index,
			)
		}
		if len(key) != 32 {
			return fmt.Errorf(
				"invalid blinding private key for issuance of input %d", index,
			)
		}
	}
	return nil
}

func validateInputIndexes(inputIndexes []uint32, p *psetv2.Pset) error {
	for _, i := range inputIndexes {
		if int(i) > int(p.Global.InputCount)-1 {
			return psetv2.ErrInputIndexOutOfRange
		}
	}
	return nil
}

func validateOutputIndexes(outputIndexes []uint32, p *psetv2.Pset) error {
	for _, i := range outputIndexes {
		if int(i) > int(p.Global.OutputCount)-1 {
			return psetv2.ErrOutputIndexOutOfRange
		}
	}
	return nil
}

func sortUnblindedOuts(
	ins []psetv2.Input, ownedIns map[uint32]psetv2.OwnedInput,
) []UnblindOutputResult {
	unblindedOuts := make([]UnblindOutputResult, len(ins))
	for _, ownedIn := range ownedIns {
		asset, _ := hex.DecodeString(ownedIn.Asset)
		unblindedOuts[ownedIn.Index] = UnblindOutputResult{
			Value:               ownedIn.Value,
			Asset:               elementsutil.ReverseBytes(asset),
			ValueBlindingFactor: ownedIn.ValueBlinder,
			AssetBlindingFactor: ownedIn.AssetBlinder,
		}
	}

	for i, unblindedOut := range unblindedOuts {
		if len(unblindedOut.Asset) == 0 {
			in := ins[i]
			unblindedOuts[i] = UnblindOutputResult{
				Asset:               in.GetUtxo().Asset,
				AssetBlindingFactor: Zero,
			}
		}
	}
	return unblindedOuts
}
