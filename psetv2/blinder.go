package psetv2

import (
	"encoding/hex"
	"fmt"
	"sort"
)

var (
	ErrOutputsToBeBlindedNotOwned           = fmt.Errorf("outputs that are supposed to be blinded are not owned by blinder")
	ErrOwnerDidntProvidedOutputBlindingData = fmt.Errorf("owner didnt provided output blinding data")
	ErrNeedUtxo                             = fmt.Errorf("input needs utxo")
	ErrInvalidBlinder                       = fmt.Errorf("invalid blinder")
	ErrGenerateSurjectionProof              = fmt.Errorf("failed to generate surjection proof, please retry")
	zeroBlinder                             = make([]byte, 32)
)

type OutputBlindingArgs struct {
	Index                uint32
	Nonce                []byte
	ValueCommitment      []byte
	AssetCommitment      []byte
	ValueRangeProof      []byte
	AssetSurjectionProof []byte
	ValueBlindProof      []byte
	AssetBlindProof      []byte
	ValueBlinder         []byte
	AssetBlinder         []byte
}

func (a OutputBlindingArgs) validate(p *Pset, isLastOutput bool) error {
	if int(a.Index) > int(p.Global.OutputCount)-1 {
		return ErrOutputIndexOutOfRange
	}
	out := p.Outputs[a.Index]
	if !out.IsBlinded() {
		return fmt.Errorf("cannot blind an output that misses blinding pubkey")
	}
	if a.Nonce == nil {
		return fmt.Errorf("missing ecdh nonce")
	}
	if len(a.Nonce) != 33 {
		return fmt.Errorf("invalid ecdh nonce length")
	}
	if a.ValueBlinder == nil {
		return fmt.Errorf("missing value blinder")
	}
	if len(a.ValueBlinder) != 32 {
		return fmt.Errorf("invalid value blinder length")
	}
	if a.AssetBlinder == nil {
		return fmt.Errorf("missing asset blinder")
	}
	if len(a.AssetBlinder) != 32 {
		return fmt.Errorf("invalid asset blinder length")
	}
	if a.AssetSurjectionProof == nil {
		return fmt.Errorf("missing asset surjetcion proof")
	}
	if a.AssetBlindProof == nil {
		return fmt.Errorf("missing asset blind proof")
	}
	if a.AssetCommitment == nil {
		return fmt.Errorf("missing asset commitment")
	}
	if len(a.AssetCommitment) != 33 {
		return fmt.Errorf("invalid asset commitment length")
	}
	if !isLastOutput {
		if a.ValueCommitment == nil {
			return fmt.Errorf("missing value commitment")
		}
		if len(a.ValueCommitment) != 33 {
			return fmt.Errorf("invalid value commitment length")
		}
		if a.ValueRangeProof == nil {
			return fmt.Errorf("missing value range proof")
		}
		if a.ValueBlindProof == nil {
			return fmt.Errorf("missing value blind proof")
		}
	}
	return nil
}

type InputIssuanceBlindingArgs struct {
	Index                   uint32
	IssuanceAsset           []byte
	IssuanceToken           []byte
	IssuanceValueCommitment []byte
	IssuanceTokenCommitment []byte
	IssuanceValueRangeProof []byte
	IssuanceTokenRangeProof []byte
	IssuanceValueBlindProof []byte
	IssuanceTokenBlindProof []byte
	IssuanceValueBlinder    []byte
	IssuanceTokenBlinder    []byte
}

func (a InputIssuanceBlindingArgs) validate(p *Pset) error {
	if int(a.Index) > int(p.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	targetInput := p.Inputs[a.Index]
	if targetInput.IssuanceValue > 0 && len(a.IssuanceValueCommitment) > 0 {
		if len(a.IssuanceValueCommitment) != 33 {
			return fmt.Errorf("invalid issuance value commitment length")
		}
		if len(a.IssuanceValueRangeProof) == 0 {
			return fmt.Errorf("missing issuance value range proof")
		}
		if len(a.IssuanceValueBlindProof) == 0 {
			return fmt.Errorf("missing issuance value blind proof")
		}
		if len(a.IssuanceValueBlinder) == 0 {
			return fmt.Errorf("missing issuance value blinder")
		}
		if len(a.IssuanceValueBlinder) != 32 {
			return fmt.Errorf("invalid issuance value blinder length")
		}
	}
	if targetInput.IssuanceInflationKeys > 0 && len(a.IssuanceTokenCommitment) > 0 {
		if len(a.IssuanceTokenCommitment) != 33 {
			return fmt.Errorf("invalid issuance token commitment length")
		}
		if len(a.IssuanceTokenRangeProof) == 0 {
			return fmt.Errorf("missing issuance token range proof")
		}
		if len(a.IssuanceTokenBlindProof) == 0 {
			return fmt.Errorf("missing issuance token blind proof")
		}
		if len(a.IssuanceTokenBlinder) == 0 {
			return fmt.Errorf("missing issuance token blinder")
		}
		if len(a.IssuanceTokenBlinder) != 32 {
			return fmt.Errorf("invalid issuance token blinder length")
		}
	}
	return nil
}

func (a InputIssuanceBlindingArgs) valueBlinder() []byte {
	if len(a.IssuanceValueBlinder) == 0 {
		return zeroBlinder
	}
	return a.IssuanceValueBlinder
}

func (a InputIssuanceBlindingArgs) tokenBlinder() []byte {
	if len(a.IssuanceTokenBlinder) == 0 {
		return zeroBlinder
	}
	return a.IssuanceTokenBlinder
}

type OwnedInput struct {
	Index        uint32
	Value        uint64
	Asset        string
	ValueBlinder []byte
	AssetBlinder []byte
}

func (i OwnedInput) validate(p *Pset) error {
	if int(i.Index) > int(p.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	prevOut := p.Inputs[i.Index].GetUtxo()
	if !prevOut.IsConfidential() {
		return nil
	}
	if i.Value == 0 {
		return fmt.Errorf("missing input value")
	}
	if len(i.Asset) == 0 {
		return fmt.Errorf("missing input asset")
	}
	buf, err := hex.DecodeString(i.Asset)
	if err != nil {
		return fmt.Errorf("input asset must be a string in hex format")
	}
	if len(buf) != 32 {
		return fmt.Errorf("invalid input asset length")
	}
	if len(i.ValueBlinder) == 0 {
		return fmt.Errorf("missing input value blinder")
	}
	if len(i.ValueBlinder) != 32 {
		return fmt.Errorf("invalid input value blinder length")
	}
	if len(i.AssetBlinder) != 32 {
		return fmt.Errorf("invalid input asset blinder length")
	}
	return nil
}

type BlinderHandler interface {
	// Checkers
	// TODO: add methods for verification of range and surjection proofs
	VerifyBlindValueProof(
		value uint64, valueCommitment, assetCommitment, proof []byte,
	) bool
	VerifyBlindAssetProof(asset, assetCommitment, proof []byte) bool
	// Scalar methods
	AddToScalarOffset(
		scalar []byte, value uint64, assetBlinder, valueBlinder []byte,
	) ([]byte, error)
	SubtractScalars(inputScalar, outputScalar []byte) ([]byte, error)
	// Last blinder methods
	LastValueCommitment(value uint64, asset, blinder []byte) ([]byte, error)
	LastBlindValueProof(
		value uint64, valueCommitment, assetCommitment, blinder []byte,
	) ([]byte, error)
	LastValueRangeProof(
		value uint64, asset, assetBlinder, valueCommitment, valueBlinder,
		scriptPubkey, nonce []byte,
	) ([]byte, error)
}

type Blinder struct {
	Pset           *Pset
	OwnedInputs    []OwnedInput
	blinderHandler BlinderHandler
}

func NewBlinder(
	p *Pset, ownedInputs []OwnedInput, blinderHandler BlinderHandler,
) (*Blinder, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid pset: %s", err)
	}
	if !p.NeedsBlinding() {
		return nil, fmt.Errorf("provided pset does not need to be blinded")
	}
	if len(ownedInputs) == 0 {
		return nil, fmt.Errorf("missing list of owned inputs")
	}

	for i, in := range ownedInputs {
		if err := in.validate(p); err != nil {
			return nil, fmt.Errorf("invalid owned input %d: %s", i, err)
		}
	}

	if blinderHandler == nil {
		return nil, fmt.Errorf("missing blinder handler")
	}

	return &Blinder{p, ownedInputs, blinderHandler}, nil
}

func (b *Blinder) Blind(
	inIssuanceBlindingArgs []InputIssuanceBlindingArgs,
	outBlindingArgs []OutputBlindingArgs, isLastBlinder bool,
) error {
	// Validate issuances blinding args
	for i, args := range inIssuanceBlindingArgs {
		if err := args.validate(b.Pset); err != nil {
			return fmt.Errorf("invalid input issuance blinding args %d: %s", i, err)
		}
	}

	// Validate output blinding args
	for i, args := range outBlindingArgs {
		isLastOuptut := isLastBlinder && i == len(outBlindingArgs)-1
		if err := args.validate(b.Pset, isLastOuptut); err != nil {
			return fmt.Errorf("invalid output blinding args %d: %s", i, err)
		}
		// Check that output can be blinded by the blinder
		out := b.Pset.Outputs[args.Index]
		if !b.ownOutput(out.BlinderIndex) {
			return fmt.Errorf("cannot blind output %d not owned by us", args.Index)
		}
		if !b.blinderHandler.VerifyBlindAssetProof(
			out.Asset, args.AssetCommitment, args.AssetBlindProof,
		) {
			return fmt.Errorf(
				"invalid output blinding args %d: failed to verify blind asset proof",
				i,
			)
		}
		if len(args.ValueBlindProof) > 0 {
			if !b.blinderHandler.VerifyBlindValueProof(
				out.Value, args.ValueCommitment, args.AssetCommitment,
				args.ValueBlindProof,
			) {
				return fmt.Errorf(
					"invalid output blinding args %d: failed to verify blind value "+
						"proof", i,
				)
			}
		}
	}

	// Make sure the blinding args are sorted by output index
	if !sort.SliceIsSorted(outBlindingArgs, func(i, j int) bool {
		return outBlindingArgs[i].Index < outBlindingArgs[j].Index
	}) {
		sort.Slice(outBlindingArgs, func(i, j int) bool {
			return outBlindingArgs[i].Index < outBlindingArgs[j].Index
		})
	}

	if b.Pset.IsFullyBlinded() {
		return nil
	}

	inputScalar, err := b.calculateInputScalar(inIssuanceBlindingArgs)
	if err != nil {
		return fmt.Errorf("failed to generate input scalar: %s", err)
	}
	outputScalar, err := b.calculateOutputScalar(
		inputScalar, outBlindingArgs, isLastBlinder,
	)
	if err != nil {
		return fmt.Errorf("failed to generate output scalar: %s", err)
	}
	lastValueBlinder, err := b.calculateLastValueBlinder(
		isLastBlinder, outBlindingArgs[len(outBlindingArgs)-1], outputScalar,
	)
	if err != nil {
		return fmt.Errorf("failed to generate last value blinder: %s", err)
	}

	p := b.Pset.Copy()

	for _, a := range inIssuanceBlindingArgs {
		p.Inputs[a.Index].IssuanceValueCommitment = a.IssuanceValueCommitment
		p.Inputs[a.Index].IssuanceValueRangeproof = a.IssuanceValueRangeProof
		p.Inputs[a.Index].IssuanceBlindValueProof = a.IssuanceValueBlindProof
		p.Inputs[a.Index].IssuanceInflationKeysCommitment = a.IssuanceTokenCommitment
		p.Inputs[a.Index].IssuanceInflationKeysRangeproof = a.IssuanceTokenRangeProof
		p.Inputs[a.Index].IssuanceBlindInflationKeysProof = a.IssuanceTokenBlindProof
	}

	for i, a := range outBlindingArgs {
		out := p.Outputs[a.Index]

		valueCommitment := a.ValueCommitment
		valueRangeProof := a.ValueRangeProof
		valueBlindProof := a.ValueBlindProof
		if isLastBlinder && i == len(outBlindingArgs)-1 {
			valueCommitment, err = b.blinderHandler.LastValueCommitment(
				out.Value, a.AssetCommitment, lastValueBlinder,
			)
			if err != nil {
				return fmt.Errorf("failed to generate last value commitment: %s", err)
			}
			valueRangeProof, err = b.blinderHandler.LastValueRangeProof(
				out.Value, out.Asset, a.AssetBlinder, valueCommitment,
				lastValueBlinder, out.Script, a.Nonce,
			)
			if err != nil {
				return fmt.Errorf("failed to generate last value range proof: %s", err)
			}
			valueBlindProof, err = b.blinderHandler.LastBlindValueProof(
				out.Value, valueCommitment, a.AssetCommitment, lastValueBlinder,
			)
			if err != nil {
				return fmt.Errorf("failed to generate last blind value proof: %s", err)
			}
		}
		p.Outputs[a.Index].ValueCommitment = valueCommitment
		p.Outputs[a.Index].ValueRangeproof = valueRangeProof
		p.Outputs[a.Index].BlindValueProof = valueBlindProof
		p.Outputs[a.Index].AssetSurjectionProof = a.AssetSurjectionProof
		p.Outputs[a.Index].AssetCommitment = a.AssetCommitment
		p.Outputs[a.Index].BlindAssetProof = a.AssetBlindProof
		p.Outputs[a.Index].EcdhPubkey = a.Nonce
		p.Outputs[a.Index].BlinderIndex = 0
	}

	if !isLastBlinder {
		p.Global.Scalars = append(b.Pset.Global.Scalars, outputScalar)
	} else {
		p.Global.Scalars = nil
		p.Global.Modifiable.Reset(0)
	}

	b.Pset.Global = p.Global
	b.Pset.Inputs = p.Inputs
	b.Pset.Outputs = p.Outputs
	return b.Pset.SanityCheck()
}

func (b *Blinder) ownOutput(blinderIndex uint32) bool {
	for _, i := range b.OwnedInputs {
		if i.Index == blinderIndex {
			return true
		}
	}
	return false
}

func (b *Blinder) calculateInputScalar(
	args []InputIssuanceBlindingArgs,
) ([]byte, error) {
	var scalar []byte
	var err error
	maybeGetIssuanceArgs := func(i uint32) *InputIssuanceBlindingArgs {
		for _, a := range args {
			if a.Index == i {
				return &a
			}
		}
		return nil
	}

	for _, ownedIn := range b.OwnedInputs {
		scalar, err = b.blinderHandler.AddToScalarOffset(
			scalar, ownedIn.Value, ownedIn.AssetBlinder, ownedIn.ValueBlinder,
		)
		if err != nil {
			return nil, err
		}
		in := b.Pset.Inputs[ownedIn.Index]
		if in.HasIssuance() {
			if issuance := maybeGetIssuanceArgs(ownedIn.Index); issuance != nil {
				scalar, err = b.blinderHandler.AddToScalarOffset(
					scalar, in.IssuanceValue, zeroBlinder, issuance.valueBlinder())
				if err != nil {
					return nil, err
				}
				if in.IssuanceInflationKeys > 0 {
					scalar, err = b.blinderHandler.AddToScalarOffset(
						scalar, in.IssuanceInflationKeys, zeroBlinder, issuance.tokenBlinder())
					if err != nil {
						return nil, err
					}

				}
			}
		}
	}
	return scalar, nil
}

func (b *Blinder) calculateOutputScalar(
	inputScalar []byte, args []OutputBlindingArgs, lastBlinder bool,
) ([]byte, error) {
	var scalar []byte
	var err error
	for _, a := range args {
		out := b.Pset.Outputs[a.Index]
		scalar, err = b.blinderHandler.AddToScalarOffset(scalar, out.Value, a.AssetBlinder, a.ValueBlinder)
		if err != nil {
			return nil, err
		}
	}
	if !lastBlinder {
		return scalar, nil
	}
	return b.blinderHandler.SubtractScalars(scalar, inputScalar)
}

func (b *Blinder) calculateLastValueBlinder(
	isLastBlinder bool, args OutputBlindingArgs, outputScalar []byte,
) ([]byte, error) {
	if !isLastBlinder {
		return nil, nil
	}

	lastBlinder, err := b.blinderHandler.SubtractScalars(args.ValueBlinder, outputScalar)
	if err != nil {
		return nil, err
	}
	for _, s := range b.Pset.Global.Scalars {
		lastBlinder, err = b.blinderHandler.SubtractScalars(lastBlinder, s)
		if err != nil {
			return nil, err
		}
	}
	return lastBlinder, nil
}
