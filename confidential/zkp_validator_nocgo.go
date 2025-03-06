//go:build !cgo

package confidential

// zkpValidator is the type that provides methods to validate zero-knowledge proofs.
type zkpValidator struct{}

// NewZKPValidator creates a new zkpValidator.
func NewZKPValidator() *zkpValidator {
	return &zkpValidator{}
}

// VerifyValueRangeProof verifies a range proof.
// This is a no-op implementation when CGO is disabled.
func (v *zkpValidator) VerifyValueRangeProof(
	valueCommitment, assetCommitment, script, proof []byte,
) bool {
	return false
}

// VerifyAssetSurjectionProof verifies a surjection proof.
// This is a no-op implementation when CGO is disabled.
func (v *zkpValidator) VerifyAssetSurjectionProof(
	inAssets, inAssetBlinders [][]byte,
	outAsset, outAssetBlinder, proof []byte,
) bool {
	return false
}

// VerifyBlindValueProof verifies a blind value proof.
// This is a no-op implementation when CGO is disabled.
func (v *zkpValidator) VerifyBlindValueProof(
	value uint64, valueCommitment, assetCommitment, proof []byte,
) bool {
	return false
}

// VerifyBlindAssetProof verifies a blind asset proof.
// This is a no-op implementation when CGO is disabled.
func (v *zkpValidator) VerifyBlindAssetProof(
	asset, assetCommitment, proof []byte,
) bool {
	return false
}
