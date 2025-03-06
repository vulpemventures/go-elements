//go:build !cgo

package confidential

import (
	"errors"

	"github.com/vulpemventures/go-elements/transaction"
)

var errNoCGO = errors.New("confidential transactions require CGO")

const (
	maxSurjectionTargets = 3
	maxScriptSize        = 10000
)

var (
	Zero = make([]byte, 32)
)

// UnblindOutputResult is the type returned by the functions that unblind tx
// outs. It contains the unblinded asset and value and also the respective
// blinding factors.
type UnblindOutputResult struct {
	Value               uint64
	Asset               []byte
	ValueBlindingFactor []byte
	AssetBlindingFactor []byte
}

// UnblindIssuanceResult is the type returned by the functions that unblind tx
// issuances. It contains the unblinded asset and token issuances.
type UnblindIssuanceResult struct {
	Asset *UnblindOutputResult
	Token *UnblindOutputResult
}

// FinalValueBlindingFactorArgs is the type used to pass arguments to the
// FinalValueBlindingFactor function.
type FinalValueBlindingFactorArgs struct {
	InValues      []uint64
	OutValues     []uint64
	InGenerators  [][]byte
	OutGenerators [][]byte
	InFactors     [][]byte
	OutFactors    [][]byte
}

// RangeProofArgs is the type used to pass arguments to the RangeProof function.
type RangeProofArgs struct {
	Value               uint64
	Nonce               [32]byte
	Asset               []byte
	AssetBlindingFactor []byte
	ValueBlindFactor    [32]byte
	ValueCommit         []byte
	ScriptPubkey        []byte
	Exp                 int
	MinBits             int
}

// SurjectionProofArgs is the type used to pass arguments to the SurjectionProof function.
type SurjectionProofArgs struct {
	OutputAsset               []byte
	OutputAssetBlindingFactor []byte
	InputAssets               [][]byte
	InputAssetBlindingFactors [][]byte
	Seed                      []byte
	NumberOfTargets           int
}

// VerifySurjectionProofArgs is the type used to pass arguments to the VerifySurjectionProof function.
type VerifySurjectionProofArgs struct {
	InputAssets               [][]byte
	InputAssetBlindingFactors [][]byte
	OutputAsset               []byte
	OutputAssetBlindingFactor []byte
	Proof                     []byte
}

// NonceHash method generates hashed secret based on ecdh.
func NonceHash(pubKey, privKey []byte) ([32]byte, error) {
	return [32]byte{}, errNoCGO
}

// UnblindOutputWithKey method unblinds a confidential transaction output with
// the given blinding private key.
func UnblindOutputWithKey(
	out *transaction.TxOutput, blindKey []byte,
) (*UnblindOutputResult, error) {
	return nil, errNoCGO
}

// UnblindOutputWithNonce method unblinds a confidential transaction output with
// the given nonce.
func UnblindOutputWithNonce(
	out *transaction.TxOutput, nonce []byte,
) (*UnblindOutputResult, error) {
	return nil, errNoCGO
}

// UnblindIssuance method unblinds a confidential transaction issuance with
// the given blinding private keys.
func UnblindIssuance(
	in *transaction.TxInput, blindKeys [][]byte,
) (*UnblindIssuanceResult, error) {
	return nil, errNoCGO
}

// FinalValueBlindingFactor method calculates the final value blinding factor.
func FinalValueBlindingFactor(
	args FinalValueBlindingFactorArgs,
) ([32]byte, error) {
	return [32]byte{}, errNoCGO
}

// AssetCommitment method creates an asset commitment.
func AssetCommitment(asset, factor []byte) ([]byte, error) {
	return nil, errNoCGO
}

// ValueCommitment method creates a value commitment.
func ValueCommitment(value uint64, generator, factor []byte) ([]byte, error) {
	return nil, errNoCGO
}

// RangeProof method creates a range proof.
func RangeProof(args RangeProofArgs) ([]byte, error) {
	return nil, errNoCGO
}

// VerifyRangeProof method verifies a range proof.
func VerifyRangeProof(valueCommitment, assetCommitment, script, proof []byte) bool {
	return false
}

// SurjectionProof method creates a surjection proof.
func SurjectionProof(args SurjectionProofArgs) ([]byte, bool) {
	return nil, false
}

// VerifySurjectionProof method verifies a surjection proof.
func VerifySurjectionProof(args VerifySurjectionProofArgs) bool {
	return false
}

// CalculateScalarOffset calculates the scalar offset for a transaction.
// This is a no-op implementation when CGO is disabled.
func CalculateScalarOffset(
	amount uint64, assetBlinder, valueBlinder []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// SubtractScalars subtracts two scalars.
// This is a no-op implementation when CGO is disabled.
func SubtractScalars(a []byte, b []byte) ([]byte, error) {
	return nil, errNoCGO
}

// ComputeAndAddToScalarOffset computes and adds to the scalar offset.
// This is a no-op implementation when CGO is disabled.
func ComputeAndAddToScalarOffset(
	scalar []byte, value uint64, assetBlinder, valueBlinder []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// CreateBlindValueProof creates a blind value proof.
// This is a no-op implementation when CGO is disabled.
func CreateBlindValueProof(
	rng func() ([]byte, error),
	valueBlinder []byte, amount uint64, valueCommitment, assetCommitment []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// CreateBlindAssetProof creates a blind asset proof.
// This is a no-op implementation when CGO is disabled.
func CreateBlindAssetProof(
	asset, assetCommitment, assetBlinder []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// VerifyBlindValueProof verifies a blind value proof.
// This is a no-op implementation when CGO is disabled.
func VerifyBlindValueProof(
	value uint64, valueCommitment, assetCommitment, proof []byte,
) bool {
	return false
}

// VerifyBlindAssetProof verifies a blind asset proof.
// This is a no-op implementation when CGO is disabled.
func VerifyBlindAssetProof(asset, assetCommitment, proof []byte) bool {
	return false
}
