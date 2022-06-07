package confidential

type zkpValidator struct{}

func NewZKPValidator() *zkpValidator {
	return &zkpValidator{}
}

func (v *zkpValidator) VerifyValueRangeProof(
	valueCommitment, assetCommitment, script, proof []byte,
) bool {
	return VerifyRangeProof(valueCommitment, assetCommitment, script, proof)
}

func (v *zkpValidator) VerifyAssetSurjectionProof(
	inAssets, inAssetBlinders [][]byte,
	outAsset, outAssetBlinder, proof []byte,
) bool {
	return VerifySurjectionProof(VerifySurjectionProofArgs{
		InputAssets:               inAssets,
		InputAssetBlindingFactors: inAssetBlinders,
		OutputAsset:               outAsset,
		OutputAssetBlindingFactor: outAssetBlinder,
		Proof:                     proof,
	})
}

func (v *zkpValidator) VerifyBlindValueProof(
	value uint64, valueCommitment, assetCommitment, proof []byte,
) bool {
	return VerifyBlindValueProof(value, valueCommitment, assetCommitment, proof)
}

func (v *zkpValidator) VerifyBlindAssetProof(
	asset, assetCommitment, proof []byte,
) bool {
	return VerifyBlindAssetProof(asset, assetCommitment, proof)
}
