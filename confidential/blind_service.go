package confidential

import "github.com/vulpemventures/go-elements/transaction"

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

type blinder struct{}

func NewBlinder() Blinder {
	return blinder{}
}

func (b blinder) AssetCommitment(
	asset,
	factor []byte,
) ([]byte, error) {
	return AssetCommitment(asset, factor)
}

func (b blinder) ValueCommitment(
	value uint64,
	generator,
	factor []byte,
) ([]byte, error) {
	return ValueCommitment(value, generator, factor)
}

func (b blinder) NonceHash(
	pubKey,
	privKey []byte,
) ([32]byte, error) {
	return NonceHash(pubKey, privKey)
}

func (b blinder) RangeProof(
	value uint64,
	nonce [32]byte,
	asset []byte,
	assetBlindingFactor []byte,
	valueBlindFactor [32]byte,
	valueCommit []byte,
	scriptPubkey []byte,
	minValue uint64,
	exp int,
	minBits int,
) ([]byte, error) {
	rangeProofArgs := RangeProofArgs{
		Value:               value,
		Nonce:               nonce,
		Asset:               asset,
		AssetBlindingFactor: assetBlindingFactor,
		ValueBlindFactor:    valueBlindFactor,
		ValueCommit:         valueCommit,
		ScriptPubkey:        scriptPubkey,
		MinValue:            minValue,
		Exp:                 exp,
		MinBits:             minBits,
	}
	return RangeProof(rangeProofArgs)
}

func (b blinder) SurjectionProof(
	outputAsset []byte,
	outputAssetBlindingFactor []byte,
	inputAssets [][]byte,
	inputAssetBlindingFactors [][]byte,
	seed []byte,
	numberOfTargets int,
) ([]byte, bool) {
	surjectionProofArgs := SurjectionProofArgs{
		OutputAsset:               outputAsset,
		OutputAssetBlindingFactor: outputAssetBlindingFactor,
		InputAssets:               inputAssets,
		InputAssetBlindingFactors: inputAssetBlindingFactors,
		Seed:                      seed,
		NumberOfTargets:           numberOfTargets,
	}

	return SurjectionProof(surjectionProofArgs)
}

func (b blinder) SubtractScalars(
	aScalar []byte,
	bScalar []byte,
) ([]byte, error) {
	return SubtractScalars(aScalar, bScalar)
}

func (b blinder) ComputeAndAddToScalarOffset(
	scalar []byte,
	value uint64,
	assetBlinder []byte,
	valueBlinder []byte,
) ([]byte, error) {
	return ComputeAndAddToScalarOffset(scalar, value, assetBlinder, valueBlinder)
}

func (b blinder) CreateBlindValueProof(
	rng func() ([]byte, error),
	valueBlindingFactor []byte,
	amount uint64,
	valueCommitment []byte,
	assetCommitment []byte,
) ([]byte, error) {
	return CreateBlindValueProof(
		rng,
		valueBlindingFactor,
		amount,
		valueCommitment,
		assetCommitment,
	)
}

func (b blinder) CreateBlindAssetProof(
	asset []byte,
	assetCommitment []byte,
	assetBlinder []byte,
) ([]byte, error) {
	return CreateBlindAssetProof(asset, assetCommitment, assetBlinder)
}

func (b blinder) VerifyBlindValueProof(
	value int64,
	valueCommitment []byte,
	blindValueProof []byte,
	assetCommitment []byte,
) (bool, error) {
	return VerifyBlindValueProof(
		value,
		valueCommitment,
		blindValueProof,
		assetCommitment,
	)
}

func (b blinder) VerifyBlindAssetProof(
	asset []byte,
	blindAssetProof []byte,
	assetCommitment []byte,
) (bool, error) {
	return VerifyBlindAssetProof(asset, blindAssetProof, assetCommitment)
}

func (b blinder) UnblindOutputWithKey(
	out *transaction.TxOutput,
	blindKey []byte,
) (uint64, []byte, []byte, []byte, error) {
	result, err := UnblindOutputWithKey(out, blindKey)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	return result.Value, result.Asset, result.ValueBlindingFactor, result.AssetBlindingFactor, err
}
