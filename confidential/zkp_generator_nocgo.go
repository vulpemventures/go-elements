//go:build !cgo

package confidential

import (
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

// zkpGenerator is the type that provides methods to generate zero-knowledge proofs.
type zkpGenerator struct {
	masterBlindingKey interface{}
	inBlindingKeys    [][]byte
	rng               func() ([]byte, error)
	ownedInputs       map[uint32]psetv2.OwnedInput
}

// NewZKPGeneratorFromMasterBlindingKey creates a new zkpGenerator from a master blinding key.
func NewZKPGeneratorFromMasterBlindingKey(
	masterBlindingKey []byte, opts interface{},
) (*zkpGenerator, error) {
	return nil, errNoCGO
}

// NewZKPGeneratorFromBlindingKeys creates a new zkpGenerator from blinding keys.
func NewZKPGeneratorFromBlindingKeys(
	inBlindingKeys [][]byte, opts interface{},
) *zkpGenerator {
	return &zkpGenerator{}
}

// ComputeAndAddToScalarOffset computes and adds to the scalar offset.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) ComputeAndAddToScalarOffset(
	scalar []byte, value uint64, assetBlinder, valueBlinder []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// SubtractScalars subtracts two scalars.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) SubtractScalars(a, b []byte) ([]byte, error) {
	return nil, errNoCGO
}

// LastValueCommitment creates a value commitment.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) LastValueCommitment(
	value uint64, asset, blinder []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// LastBlindValueProof creates a blind value proof.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) LastBlindValueProof(
	value uint64, valueCommitment, assetCommitment, blinder []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// LastValueRangeProof creates a range proof.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) LastValueRangeProof(
	value uint64, asset, assetBlinder, valueCommitment, valueBlinder,
	scriptPubkey, nonce []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// UnblindInputs unblinds inputs.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) UnblindInputs(
	p *psetv2.Pset, inputIndexes []uint32,
) ([]psetv2.OwnedInput, error) {
	return nil, errNoCGO
}

// BlindIssuances blinds issuances.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) BlindIssuances(
	p *psetv2.Pset, blindingKeysByIndex map[uint32][]byte,
) ([]psetv2.InputIssuanceBlindingArgs, error) {
	return nil, errNoCGO
}

// BlindOutputs blinds outputs.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) BlindOutputs(
	p *psetv2.Pset, outputIndexes []uint32,
) ([]psetv2.OutputBlindingArgs, error) {
	return nil, errNoCGO
}

// unblindOutput unblinds an output.
// This is a no-op implementation when CGO is disabled.
func (g *zkpGenerator) unblindOutput(
	out *transaction.TxOutput,
) (*psetv2.OwnedInput, error) {
	return nil, errNoCGO
}
