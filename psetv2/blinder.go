package psetv2

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/vulpemventures/go-elements/elementsutil"
)

const (
	isLastBlinder = true
)

var (
	zeroBlinder = make([]byte, 32)

	// Output errors
	ErrOutMissingBlindingKey = fmt.Errorf(
		"cannot blind an output that misses blinding pubkey",
	)
	ErrOutMissingNonce                = fmt.Errorf("missing output ecdh pubkey")
	ErrOutMissingNonceCommitment      = fmt.Errorf("missing output nonce commitment")
	ErrOutMissingAssetBlinder         = fmt.Errorf("missing output asset blinder")
	ErrOutMissingAssetCommitment      = fmt.Errorf("missing output asset commitment")
	ErrOutMissingAssetSurjectionProof = fmt.Errorf("missing output asset surjetcion proof")
	ErrOutMissingAssetBlindProof      = fmt.Errorf("missing output asset commitment or blind proof")
	ErrOutMissingValueBlinder         = fmt.Errorf("missing output value blinder")
	ErrOutMissingValueCommitment      = fmt.Errorf("missing output value commitment")
	ErrOutMissingValueRangeProof      = fmt.Errorf("missing output value range proof")
	ErrOutMissingValueBlindProof      = fmt.Errorf("missing output value commitment or blind proof")
	ErrOutInvalidNonce                = fmt.Errorf("invalid output ecdh pubkey length")
	ErrOutInvalidNonceCommitment      = fmt.Errorf("invalid output nonce commitment length")
	ErrOutInvalidValueBlinder         = fmt.Errorf("invalid output value blinder length")
	ErrOutInvalidAssetBlinder         = fmt.Errorf("invalid output asset blinder length")
	ErrOutInvalidAssetCommitment      = fmt.Errorf("invalid output asset commitment length")
	ErrOutInvalidValueCommitment      = fmt.Errorf("invalid output value commitment length")

	// Input issuance errors
	ErrInIssuanceMissingValueBlinder    = fmt.Errorf("missing issuance value blinder")
	ErrInIssuanceMissingValueCommitment = fmt.Errorf("missing issuance value commitment")
	ErrInIssuanceMissingValueRangeProof = fmt.Errorf("missing issuance value range proof")
	ErrInIssuanceMissingValueBlindProof = fmt.Errorf("missing issuance value blind proof")
	ErrInIssuanceMissingTokenBlinder    = fmt.Errorf("missing issuance token value blinder")
	ErrInIssuanceMissingTokenCommitment = fmt.Errorf("missing issuance token value commitment")
	ErrInIssuanceMissingTokenRangeProof = fmt.Errorf("missing issuance token value range proof")
	ErrInIssuanceMissingTokenBlindProof = fmt.Errorf("missing issuance token value blind proof")
	ErrInIssuanceInvalidValueBlinder    = fmt.Errorf("invalid issuance value blinder length")
	ErrInIssuanceInvalidValueCommitment = fmt.Errorf("invalid issuance value commitment length")
	ErrInIssuanceInvalidTokenBlinder    = fmt.Errorf("invalid issuance token value blinder length")
	ErrInIssuanceInvalidTokenCommitment = fmt.Errorf("invalid issuance token value commitment length")

	// Input errors
	ErrOwnedInMissingValue        = fmt.Errorf("missing input value")
	ErrOwnedInMissingAsset        = fmt.Errorf("missing input asset")
	ErrOwnedInMissingValueBlinder = fmt.Errorf("missing input value blinder")
	ErrOwnedInMissingAssetBlinder = fmt.Errorf("missing input asset blinder")
	ErrOwnedInInvalidAsset        = fmt.Errorf("invalid input asset length")
	ErrOwnedInInvalidAssetFormat  = fmt.Errorf("input asset must be a string in hex format")
	ErrOwnedInInvalidValueBlinder = fmt.Errorf("invalid input value blinder length")
	ErrOwnedInInvalidAssetBlinder = fmt.Errorf("invalid input asset blinder length")

	// Blinder errors
	ErrBlinderForbiddenBlinding  = fmt.Errorf("provided pset does not need to be blinded")
	ErrBlinderMissingOwnedInputs = fmt.Errorf("missing list of owned inputs")
	ErrBlinderMissingValidator   = fmt.Errorf("missing blinding validator")
	ErrBlinderMissingGenerator   = fmt.Errorf("missing blinding generator")
)

type OutputBlindingArgs struct {
	Index                uint32
	Nonce                []byte
	NonceCommitment      []byte
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
	if !out.NeedsBlinding() {
		return ErrOutMissingBlindingKey
	}
	if a.Nonce == nil {
		return ErrOutMissingNonce
	}
	if len(a.Nonce) != 32 {
		return ErrOutInvalidNonce
	}
	if a.NonceCommitment == nil {
		return ErrOutMissingNonceCommitment
	}
	if len(a.NonceCommitment) != 33 {
		return ErrOutInvalidNonceCommitment
	}
	if a.ValueBlinder == nil {
		return ErrOutMissingValueBlinder
	}
	if len(a.ValueBlinder) != 32 {
		return ErrOutInvalidValueBlinder
	}
	if a.AssetBlinder == nil {
		return ErrOutMissingAssetBlinder
	}
	if len(a.AssetBlinder) != 32 {
		return ErrOutInvalidAssetBlinder
	}
	if a.AssetCommitment == nil {
		return ErrOutMissingAssetCommitment
	}
	if len(a.AssetCommitment) != 33 {
		return ErrOutInvalidAssetCommitment
	}
	if a.AssetSurjectionProof == nil {
		return ErrOutMissingAssetSurjectionProof
	}
	if a.AssetBlindProof == nil {
		return ErrOutMissingAssetBlindProof
	}
	if !isLastOutput {
		if a.ValueCommitment == nil {
			return ErrOutMissingValueCommitment
		}
		if len(a.ValueCommitment) != 33 {
			return ErrOutInvalidValueCommitment
		}
		if a.ValueRangeProof == nil {
			return ErrOutMissingValueRangeProof
		}
		if a.ValueBlindProof == nil {
			return ErrOutMissingValueBlindProof
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
		if len(a.IssuanceValueCommitment) == 0 {
			if len(a.IssuanceValueBlinder) == 0 {
				return ErrInIssuanceMissingValueBlindProof
			}
			if len(a.IssuanceValueBlinder) != 32 {
				return ErrInIssuanceInvalidValueBlinder
			}
			return ErrInIssuanceMissingValueCommitment
		}
		if len(a.IssuanceValueCommitment) != 33 {
			return ErrInIssuanceInvalidValueCommitment
		}
		if len(a.IssuanceValueRangeProof) == 0 {
			return ErrInIssuanceMissingValueRangeProof
		}
		if len(a.IssuanceValueBlindProof) == 0 {
			return ErrInIssuanceMissingValueBlindProof
		}
	}
	if targetInput.IssuanceInflationKeys > 0 && len(a.IssuanceTokenCommitment) > 0 {
		if len(a.IssuanceTokenBlinder) == 0 {
			return ErrInIssuanceMissingTokenBlinder
		}
		if len(a.IssuanceTokenBlinder) != 32 {
			return ErrInIssuanceInvalidTokenBlinder
		}
		if len(a.IssuanceTokenCommitment) == 0 {
			return ErrInIssuanceMissingTokenCommitment
		}
		if len(a.IssuanceTokenCommitment) != 33 {
			return ErrInIssuanceInvalidTokenCommitment
		}
		if len(a.IssuanceTokenRangeProof) == 0 {
			return ErrInIssuanceMissingTokenRangeProof
		}
		if len(a.IssuanceTokenBlindProof) == 0 {
			return ErrInIssuanceMissingTokenBlindProof
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
	prevout := p.Inputs[i.Index].GetUtxo()
	if prevout == nil {
		return fmt.Errorf("missing input prevout")
	}
	if !prevout.IsConfidential() {
		return nil
	}
	if i.Value == 0 {
		return ErrOwnedInMissingValue
	}
	if len(i.Asset) == 0 {
		return ErrOwnedInMissingAsset
	}
	buf, err := hex.DecodeString(i.Asset)
	if err != nil {
		return ErrOwnedInInvalidAssetFormat
	}
	if len(buf) != 32 {
		return ErrOwnedInInvalidAsset
	}
	if len(i.ValueBlinder) == 0 {
		return ErrOwnedInMissingValueBlinder
	}
	if len(i.ValueBlinder) != 32 {
		return ErrOwnedInInvalidValueBlinder
	}
	if len(i.AssetBlinder) == 0 {
		return ErrOwnedInMissingAssetBlinder
	}
	if len(i.AssetBlinder) != 32 {
		return ErrOwnedInInvalidAssetBlinder
	}
	return nil
}

type BlindingValidator interface {
	VerifyValueRangeProof(
		valueCommitment, assetCommitment, script, proof []byte,
	) bool
	VerifyAssetSurjectionProof(
		inAssets, inAssetBlinders [][]byte,
		outAsset, outAssetBlinder, proof []byte,
	) bool
	VerifyBlindValueProof(
		value uint64, valueCommitment, assetCommitment, proof []byte,
	) bool
	VerifyBlindAssetProof(asset, assetCommitment, proof []byte) bool
}

type BlindingGenerator interface {
	// Scalar methods
	ComputeAndAddToScalarOffset(
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
	Pset        *Pset
	OwnedInputs []OwnedInput
	validator   BlindingValidator
	generator   BlindingGenerator
}

func NewBlinder(
	p *Pset, ownedInputs []OwnedInput,
	validator BlindingValidator, generator BlindingGenerator,
) (*Blinder, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid pset: %s", err)
	}
	if !p.NeedsBlinding() {
		return nil, ErrBlinderForbiddenBlinding
	}
	if len(ownedInputs) == 0 {
		return nil, ErrBlinderMissingOwnedInputs
	}

	for i, in := range ownedInputs {
		if err := in.validate(p); err != nil {
			return nil, fmt.Errorf("invalid owned input %d: %s", i, err)
		}
	}

	if validator == nil {
		return nil, ErrBlinderMissingValidator
	}
	if generator == nil {
		return nil, ErrBlinderMissingGenerator
	}

	return &Blinder{p, ownedInputs, validator, generator}, nil
}

func (b *Blinder) BlindNonLast(
	inIssuanceBlindingArgs []InputIssuanceBlindingArgs,
	outBlindingArgs []OutputBlindingArgs,
) error {
	return b.blind(inIssuanceBlindingArgs, outBlindingArgs, !isLastBlinder)
}

func (b *Blinder) BlindLast(
	inIssuanceBlindingArgs []InputIssuanceBlindingArgs,
	outBlindingArgs []OutputBlindingArgs,
) error {
	return b.blind(inIssuanceBlindingArgs, outBlindingArgs, isLastBlinder)
}

func (b *Blinder) blind(
	inIssuanceBlindingArgs []InputIssuanceBlindingArgs,
	outBlindingArgs []OutputBlindingArgs, isLastBlinder bool,
) error {
	if b.Pset.IsFullyBlinded() {
		return nil
	}

	// Validate issuances blinding args
	for i, args := range inIssuanceBlindingArgs {
		if err := args.validate(b.Pset); err != nil {
			return fmt.Errorf("invalid input issuance blinding args %d: %s", i, err)
		}
	}

	// Make sure blinding args are ordered by index before validating.
	sort.Slice(outBlindingArgs, func(i, j int) bool {
		return outBlindingArgs[i].Index < outBlindingArgs[j].Index
	})
	// Validate output blinding args
	for i, args := range outBlindingArgs {
		isLastOuptut := isLastBlinder && i == len(outBlindingArgs)-1
		if err := args.validate(b.Pset, isLastOuptut); err != nil {
			return fmt.Errorf("invalid output blinding args %d: %s", i, err)
		}
	}

	if err := b.validateBlindingArgs(
		isLastBlinder, outBlindingArgs,
	); err != nil {
		return err
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
			valueCommitment, err = b.generator.LastValueCommitment(
				out.Value, a.AssetCommitment, lastValueBlinder,
			)
			if err != nil {
				return fmt.Errorf("failed to generate last value commitment: %s", err)
			}
			valueRangeProof, err = b.generator.LastValueRangeProof(
				out.Value, out.Asset, a.AssetBlinder, valueCommitment,
				lastValueBlinder, out.Script, a.Nonce,
			)
			if err != nil {
				return fmt.Errorf("failed to generate last value range proof: %s", err)
			}
			valueBlindProof, err = b.generator.LastBlindValueProof(
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
		p.Outputs[a.Index].EcdhPubkey = a.NonceCommitment
		p.Outputs[a.Index].BlinderIndex = 0
	}

	if !isLastBlinder {
		p.Global.Scalars = append(b.Pset.Global.Scalars, outputScalar)
	} else {
		p.Global.Scalars = nil
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

func (b *Blinder) validateBlindingArgs(
	isLastBlinder bool, outBlindingArgs []OutputBlindingArgs,
) error {
	isOwnedInput := func(index int) *OwnedInput {
		for _, ownedIn := range b.OwnedInputs {
			if ownedIn.Index == uint32(index) {
				return &ownedIn
			}
		}
		return nil
	}

	inAssets := make([][]byte, 0, b.Pset.Global.InputCount)
	inAssetBlinders := make([][]byte, 0, b.Pset.Global.InputCount)
	inIssuanceAssets := make([][]byte, 0, b.Pset.Global.InputCount)
	inIssuanceAssetBlinders := make([][]byte, 0, b.Pset.Global.InputCount)
	for i, in := range b.Pset.Inputs {
		var asset, assetBlinder []byte
		if ownedIn := isOwnedInput(i); ownedIn != nil {
			buf, _ := elementsutil.AssetHashToBytes(ownedIn.Asset)
			asset = buf[1:]
			assetBlinder = ownedIn.AssetBlinder
		} else {
			prevout := in.GetUtxo()
			if prevout == nil {
				return fmt.Errorf("missing input prevout")
			}
			asset = prevout.Asset
			assetBlinder = zeroBlinder
		}
		inAssets = append(inAssets, asset)
		inAssetBlinders = append(inAssetBlinders, assetBlinder)

		if in.HasIssuance() {
			inIssuanceAssets = append(inIssuanceAssets, in.GetIssuanceAssetHash())
			inIssuanceAssetBlinders = append(inIssuanceAssetBlinders, zeroBlinder)
			if in.IssuanceInflationKeys > 0 {
				inIssuanceAssets = append(inIssuanceAssets, in.GetIssuanceInflationKeysHash())
				inIssuanceAssetBlinders = append(inIssuanceAssetBlinders, zeroBlinder)
			}
		}
	}

	inAssets = append(inAssets, inIssuanceAssets...)
	inAssetBlinders = append(inAssetBlinders, inIssuanceAssetBlinders...)

	for i, args := range outBlindingArgs {
		// Check that output can be blinded by the blinder
		out := b.Pset.Outputs[args.Index]
		if !b.ownOutput(out.BlinderIndex) {
			return fmt.Errorf("cannot blind output %d not owned by us", args.Index)
		}
		if !b.validator.VerifyAssetSurjectionProof(
			inAssets, inAssetBlinders, out.Asset, args.AssetBlinder,
			args.AssetSurjectionProof,
		) {
			return fmt.Errorf(
				"invalid output %d blinding args: failed to verify asset surjection "+
					"proof", args.Index,
			)
		}
		if !b.validator.VerifyBlindAssetProof(
			out.Asset, args.AssetCommitment, args.AssetBlindProof,
		) {
			return fmt.Errorf(
				"invalid output %d blinding args: failed to verify blind asset proof",
				args.Index,
			)
		}
		lastBlindingArgs := isLastBlinder && i == len(outBlindingArgs)-1
		if !lastBlindingArgs {
			if !b.validator.VerifyValueRangeProof(
				args.ValueCommitment, args.AssetCommitment, out.Script, args.ValueRangeProof,
			) {
				return fmt.Errorf(
					"invalid output %d blinding args: failed to verify value range proof",
					args.Index,
				)
			}
			if !b.validator.VerifyBlindValueProof(
				out.Value, args.ValueCommitment, args.AssetCommitment,
				args.ValueBlindProof,
			) {
				return fmt.Errorf(
					"invalid output %d blinding args: failed to verify blind value "+
						"proof", args.Index,
				)
			}
		}
	}

	return nil
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
		scalar, err = b.generator.ComputeAndAddToScalarOffset(
			scalar, ownedIn.Value, ownedIn.AssetBlinder, ownedIn.ValueBlinder,
		)
		if err != nil {
			return nil, err
		}
		in := b.Pset.Inputs[ownedIn.Index]
		if in.HasIssuance() {
			if issuance := maybeGetIssuanceArgs(ownedIn.Index); issuance != nil {
				scalar, err = b.generator.ComputeAndAddToScalarOffset(
					scalar, in.IssuanceValue, zeroBlinder, issuance.valueBlinder())
				if err != nil {
					return nil, err
				}
				if in.IssuanceInflationKeys > 0 {
					scalar, err = b.generator.ComputeAndAddToScalarOffset(
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
		scalar, err = b.generator.ComputeAndAddToScalarOffset(scalar, out.Value, a.AssetBlinder, a.ValueBlinder)
		if err != nil {
			return nil, err
		}
	}
	if !lastBlinder {
		return scalar, nil
	}
	return b.generator.SubtractScalars(scalar, inputScalar)
}

func (b *Blinder) calculateLastValueBlinder(
	isLastBlinder bool, args OutputBlindingArgs, outputScalar []byte,
) ([]byte, error) {
	if !isLastBlinder {
		return nil, nil
	}

	lastBlinder, err := b.generator.SubtractScalars(args.ValueBlinder, outputScalar)
	if err != nil {
		return nil, err
	}
	for _, s := range b.Pset.Global.Scalars {
		lastBlinder, err = b.generator.SubtractScalars(lastBlinder, s)
		if err != nil {
			return nil, err
		}
	}
	return lastBlinder, nil
}
