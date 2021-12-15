package confidential

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/vulpemventures/go-elements/transaction"
	"github.com/vulpemventures/go-secp256k1-zkp"
)

var (
	ErrPrivKeyMult         = errors.New("privKey mult error")
	ErrPrivKeyTweakAdd     = errors.New("privKey tweak add error")
	ErrPrivKeyNegate       = errors.New("privKey negate error")
	ErrInvalidValueBlinder = errors.New("invalid value blinder")
)

const (
	maxSurjectionTargets = 3
)

var (
	Zero = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

// NonceHash method generates hashed secret based on ecdh.
func NonceHash(pubKey, privKey []byte) (
	result [32]byte,
	err error,
) {
	return nonceHash(pubKey, privKey)
}

// UnblindOutputResult is the type returned by the functions that unblind tx
// outs. It contains the unblinded asset and value and also the respective
// blinding factors.
type UnblindOutputResult struct {
	Value               uint64
	Asset               []byte
	ValueBlindingFactor []byte
	AssetBlindingFactor []byte
}

// UnblindOutputWithKey method unblinds a confidential transaction output with
// the given blinding private key.
func UnblindOutputWithKey(
	out *transaction.TxOutput,
	blindKey []byte,
) (*UnblindOutputResult, error) {
	if !out.IsConfidential() {
		return nil, nil
	}

	nonce, err := NonceHash(out.Nonce, blindKey)
	if err != nil {
		return nil, err
	}
	return unblindOutput(out, nonce)
}

// UnblindOutputWithNonce method unblinds a confidential transaction output with
// the given ecdh nonce calculated for example with the above NonceHash func.
func UnblindOutputWithNonce(
	out *transaction.TxOutput,
	nonce []byte,
) (*UnblindOutputResult, error) {
	if !out.IsConfidential() {
		return nil, nil
	}

	var nonce32 [32]byte
	copy(nonce32[:], nonce)
	return unblindOutput(out, nonce32)
}

type UnblindIssuanceResult struct {
	Asset *UnblindOutputResult
	Token *UnblindOutputResult
}

func UnblindIssuance(
	in *transaction.TxInput,
	blindKeys [][]byte,
) (*UnblindIssuanceResult, error) {
	return unblindIssuance(in, blindKeys)
}

// FinalValueBlindingFactorArgs is the type provided to the function that
// calculates the blinder of the last output of a tx.
type FinalValueBlindingFactorArgs struct {
	InValues      []uint64
	OutValues     []uint64
	InGenerators  [][]byte
	OutGenerators [][]byte
	InFactors     [][]byte
	OutFactors    [][]byte
}

// FinalValueBlindingFactor method calculates the blinder as the sum of all
// previous blinders of a tx.
func FinalValueBlindingFactor(args FinalValueBlindingFactorArgs) (
	[32]byte, error,
) {
	return finalValueBlindingFactor(args)
}

// AssetCommitment method generates asset commitment
func AssetCommitment(asset, factor []byte) ([]byte, error) {
	return assetCommitment(asset, factor)
}

// ValueCommitment method generates value commitment
func ValueCommitment(value uint64, generator, factor []byte) ([]byte, error) {
	return valueCommitment(value, generator, factor)
}

type RangeProofArgs struct {
	Value               uint64
	Nonce               [32]byte
	Asset               []byte
	AssetBlindingFactor []byte
	ValueBlindFactor    [32]byte
	ValueCommit         []byte
	ScriptPubkey        []byte
	MinValue            uint64
	Exp                 int
	MinBits             int
}

func (a RangeProofArgs) minValue() uint64 {
	if a.MinValue <= 0 {
		return 1
	}
	return a.MinValue
}

func (a RangeProofArgs) exp() int {
	if a.Exp < -1 || a.Exp > 18 {
		return 0
	}
	return a.Exp
}

func (a RangeProofArgs) minBits() int {
	if a.MinBits <= 0 {
		return 36
	}
	return a.MinBits
}

// RangeProof method calculates range proof
func RangeProof(args RangeProofArgs) ([]byte, error) {
	fmt.Println("**")
	fmt.Printf("value: %v\n", args.Value)
	fmt.Printf("nonce: %v\n", args.Nonce)
	fmt.Printf("asset: %v\n", args.Asset)
	fmt.Printf("assetBlindingFactor: %v\n", args.AssetBlindingFactor)
	fmt.Printf("valueBlindFactor: %v\n", args.ValueBlindFactor)
	fmt.Printf("valueCommit: %v\n", args.ValueCommit)
	fmt.Printf("scriptPubkey: %v\n", args.ScriptPubkey)
	fmt.Printf("minValue: %v\n", args.MinValue)
	fmt.Printf("exp: %v\n", args.Exp)
	fmt.Printf("minBits: %v\n", args.MinBits)
	fmt.Println("**")
	return rangeProof(args)
}

type SurjectionProofArgs struct {
	OutputAsset               []byte
	OutputAssetBlindingFactor []byte
	InputAssets               [][]byte
	InputAssetBlindingFactors [][]byte
	Seed                      []byte
	NumberOfTargets           int
}

func (a SurjectionProofArgs) nInputsToUse() int {
	numOfTargets := maxSurjectionTargets
	if a.NumberOfTargets > 0 {
		numOfTargets = a.NumberOfTargets
	}

	min := numOfTargets
	if len(a.InputAssets) < min {
		min = len(a.InputAssets)
	}

	return min
}

//SurjectionProof method generates surjection proof
func SurjectionProof(args SurjectionProofArgs) ([]byte, bool) {
	return surjectionProof(args)
}

type VerifySurjectionProofArgs struct {
	InputAssets               [][]byte
	InputAssetBlindingFactors [][]byte
	OutputAsset               []byte
	OutputAssetBlindingFactor []byte
	Proof                     []byte
}

// VerifySurjectionProof method verifies the validity of a surjection proof
func VerifySurjectionProof(args VerifySurjectionProofArgs) bool {
	return verifySurjectionProof(args)
}

func nonceHash(pubKey, privKey []byte) (result [32]byte, err error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	_, publicKey, err := secp256k1.EcPubkeyParse(ctx, pubKey)
	if err != nil {
		return
	}

	_, ecdh, err := secp256k1.Ecdh(ctx, publicKey, privKey)
	if err != nil {
		return
	}

	result = sha256.Sum256(ecdh)
	return
}

func unblindOutput(
	out *transaction.TxOutput,
	nonce [32]byte,
) (*UnblindOutputResult, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	valueCommit, err := secp256k1.CommitmentParse(ctx, out.Value)
	if err != nil {
		return nil, err
	}

	var gen *secp256k1.Generator
	if len(out.Asset) == 33 {
		gen, err = secp256k1.GeneratorFromBytes(out.Asset)
	} else {
		gen, err = secp256k1.GeneratorGenerate(ctx, out.Asset)
	}
	if err != nil {
		return nil, err
	}

	rewind, value, _, _, message, err := secp256k1.RangeProofRewind(
		ctx,
		valueCommit,
		out.RangeProof,
		nonce,
		out.Script,
		gen,
	)
	if err != nil {
		return nil, err
	}

	return &UnblindOutputResult{
		Value:               value,
		Asset:               message[:32],
		ValueBlindingFactor: rewind[:],
		AssetBlindingFactor: message[32:],
	}, nil
}

func unblindIssuance(
	in *transaction.TxInput,
	blindKeys [][]byte,
) (*UnblindIssuanceResult, error) {
	if len(blindKeys) <= 1 {
		return nil, errors.New("missing asset blind private key")
	}
	if !in.HasAnyIssuance() {
		return nil, errors.New("missing input issuance")
	}
	if !in.HasConfidentialIssuance() {
		return nil, errors.New("missing asset range proof")
	}

	if in.Issuance.HasTokenAmount() {
		if len(in.InflationRangeProof) <= 0 {
			return nil, errors.New("missing token range proof")
		}
		if len(blindKeys) < 1 {
			return nil, errors.New("missing token blind private key")
		}
	}

	asset, err := calcAssetHash(in)
	if err != nil {
		return nil, err
	}

	outs := []*transaction.TxOutput{
		&transaction.TxOutput{
			Asset:      asset,
			Value:      in.Issuance.AssetAmount,
			RangeProof: in.IssuanceRangeProof,
			Script:     make([]byte, 0),
		},
	}
	if in.Issuance.HasTokenAmount() {
		token, err := calcTokenHash(in)
		if err != nil {
			return nil, err
		}

		outs = append(outs, &transaction.TxOutput{
			Asset:      token,
			Value:      in.Issuance.TokenAmount,
			RangeProof: in.InflationRangeProof,
			Script:     make([]byte, 0),
		})
	}

	res := &UnblindIssuanceResult{}
	for i, out := range outs {
		var nonce [32]byte
		copy(nonce[:], blindKeys[i])
		unblinded, err := unblindOutput(out, nonce)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			res.Asset = unblinded
			res.Asset.Asset = out.Asset
			res.Asset.AssetBlindingFactor = make([]byte, 32)
		} else {
			res.Token = unblinded
			res.Token.Asset = out.Asset
			res.Token.AssetBlindingFactor = make([]byte, 32)
		}
	}
	return res, nil
}

func finalValueBlindingFactor(args FinalValueBlindingFactorArgs) (
	[32]byte, error,
) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	values := append(args.InValues, args.OutValues...)

	generatorBlind := make([][]byte, 0)
	generatorBlind = append(generatorBlind, args.InGenerators...)
	generatorBlind = append(generatorBlind, args.OutGenerators...)

	blindingFactor := make([][]byte, 0)
	blindingFactor = append(blindingFactor, args.InFactors...)
	blindingFactor = append(blindingFactor, args.OutFactors...)

	return secp256k1.BlindGeneratorBlindSum(
		ctx,
		values,
		generatorBlind,
		blindingFactor,
		len(args.InValues),
	)
}

func assetCommitment(asset []byte, factor []byte) ([]byte, error) {
	generator, err := outAssetGenerator(asset, factor)
	if err != nil {
		return nil, err
	}
	assetCommitment := generator.Bytes()
	return assetCommitment[:], nil
}

func valueCommitment(value uint64, generator, factor []byte) ([]byte, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	gen, err := secp256k1.GeneratorParse(ctx, generator)
	if err != nil {
		return nil, err
	}

	commit, err := secp256k1.Commit(ctx, factor, value, gen)
	if err != nil {
		return nil, err
	}

	valueCommitment := commit.Bytes()
	return valueCommitment[:], nil
}

func rangeProof(args RangeProofArgs) ([]byte, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	generator, err := outAssetGenerator(args.Asset, args.AssetBlindingFactor)
	if err != nil {
		return nil, err
	}

	message := append(args.Asset, args.AssetBlindingFactor...)

	commit, err := secp256k1.CommitmentParse(ctx, args.ValueCommit)
	if err != nil {
		return nil, err
	}

	return secp256k1.RangeProofSign(
		ctx,
		args.minValue(),
		commit,
		args.ValueBlindFactor,
		args.Nonce,
		args.exp(),
		args.minBits(),
		args.Value,
		message,
		args.ScriptPubkey,
		generator,
	)
}

func surjectionProof(args SurjectionProofArgs) ([]byte, bool) {
	if args.NumberOfTargets > maxSurjectionTargets {
		return nil, false
	}

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	inputGenerators, err := inAssetGenerators(
		args.InputAssets,
		args.InputAssetBlindingFactors,
	)
	if err != nil {
		return nil, false
	}

	fixedInputTags, err := inFixedTags(args.InputAssets)
	if err != nil {
		return nil, false
	}

	fixedOutputTag, err := outFixedTag(args.OutputAsset)
	if err != nil {
		return nil, false
	}

	outputGenerator, err := outAssetGenerator(
		args.OutputAsset,
		args.OutputAssetBlindingFactor,
	)
	if err != nil {
		return nil, false
	}

	maxIterations := 100
	proof, inputIndex, err := secp256k1.SurjectionProofInitialize(
		ctx,
		fixedInputTags,
		args.nInputsToUse(),
		fixedOutputTag,
		maxIterations,
		args.Seed,
	)
	if err != nil {
		return nil, false
	}

	err = secp256k1.SurjectionProofGenerate(
		ctx,
		proof,
		inputGenerators,
		outputGenerator,
		inputIndex,
		args.InputAssetBlindingFactors[inputIndex],
		args.OutputAssetBlindingFactor,
	)
	if err != nil {
		return nil, false
	}

	if !secp256k1.SurjectionProofVerify(
		ctx,
		proof,
		inputGenerators,
		outputGenerator,
	) {
		return nil, false
	}

	return proof.Bytes(), true
}

func verifySurjectionProof(args VerifySurjectionProofArgs) bool {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	inGenerators, err := inAssetGenerators(
		args.InputAssets,
		args.InputAssetBlindingFactors,
	)
	if err != nil {
		return false
	}

	outGenerator, err := outAssetGenerator(
		args.OutputAsset,
		args.OutputAssetBlindingFactor,
	)
	if err != nil {
		return false
	}

	proof, err := secp256k1.SurjectionProofParse(ctx, args.Proof)
	if err != nil {
		return false
	}

	return secp256k1.SurjectionProofVerify(
		ctx,
		proof,
		inGenerators,
		outGenerator,
	)
}

func inAssetGenerators(inAssets, inAssetBlinders [][]byte) ([]*secp256k1.Generator, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	inGenerators := make([]*secp256k1.Generator, 0, len(inAssets))
	for i, inAsset := range inAssets {
		gen, err := secp256k1.GeneratorGenerateBlinded( //TODO in elements repo generate_blinded is not used?
			ctx,
			inAsset,
			inAssetBlinders[i],
		)
		if err != nil {
			return nil, err
		}
		inGenerators = append(inGenerators, gen)
	}
	return inGenerators, nil
}

func outAssetGenerator(outAsset, outAssetBlinder []byte) (*secp256k1.Generator, error) {
	res, err := inAssetGenerators([][]byte{outAsset}, [][]byte{outAssetBlinder})
	if err != nil {
		return nil, err
	}
	outGenerator := res[0]
	return outGenerator, nil
}

func inFixedTags(inAssets [][]byte) ([]*secp256k1.FixedAssetTag, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	fixedInputTags := make([]*secp256k1.FixedAssetTag, 0, len(inAssets))
	for _, inTag := range inAssets {
		fixedAssetTag, err := secp256k1.FixedAssetTagParse(inTag)
		if err != nil {
			return nil, err
		}
		fixedInputTags = append(fixedInputTags, fixedAssetTag)
	}
	return fixedInputTags, nil
}

func outFixedTag(outAsset []byte) (*secp256k1.FixedAssetTag, error) {
	res, err := inFixedTags([][]byte{outAsset})
	if err != nil {
		return nil, err
	}
	outFixedTag := res[0]
	return outFixedTag, nil
}

func calcAssetHash(in *transaction.TxInput) ([]byte, error) {
	iss, err := transaction.NewTxIssuanceFromInput(in)
	if err != nil {
		return nil, err
	}
	return iss.GenerateAsset()
}

func calcTokenHash(in *transaction.TxInput) ([]byte, error) {
	iss, err := transaction.NewTxIssuanceFromInput(in)
	if err != nil {
		return nil, err
	}
	return iss.GenerateReissuanceToken(1)
}

func calcIssuance(in *transaction.TxInput) *transaction.TxIssuanceExtended {
	var issuance *transaction.TxIssuanceExtended
	if in.Issuance.IsReissuance() {
		issuance = transaction.NewTxIssuanceFromEntropy(in.Issuance.AssetEntropy)
	} else {
		issuance = transaction.NewTxIssuanceFromContractHash(in.Issuance.AssetEntropy)
		issuance.GenerateEntropy(in.Hash, in.Index)
	}
	return issuance
}

// CalculateScalarOffset computes the scalar offset used for the final blinder computation
// value * asset_blinder + value_blinder
func CalculateScalarOffset(
	amount uint64,
	assetBlinder []byte,
	valueBlinder []byte,
) ([]byte, error) {
	var result []byte

	var ab []byte
	if assetBlinder != nil {
		ab = make([]byte, len(assetBlinder))
		copy(ab, assetBlinder)
	}

	var vb []byte
	if valueBlinder != nil {
		vb = make([]byte, len(valueBlinder))
		copy(vb, valueBlinder)
	}

	if ab == nil {
		return vb, nil
	}

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	result = ab

	val := make([]byte, 32)
	binary.BigEndian.PutUint64(val[24:], amount)

	if amount > 0 {
		r, err := secp256k1.EcPrivKeyTweakMul(ctx, result, val)
		if err != nil {
			return nil, err
		}
		if r != 1 {
			return nil, ErrPrivKeyMult
		}
	} else {
		return vb, nil
	}

	if vb == nil {
		return nil, ErrInvalidValueBlinder
	}

	var vn []byte
	if valueBlinder != nil {
		vn = make([]byte, len(valueBlinder))
		copy(vn, valueBlinder)
	}
	r, err := secp256k1.EcPrivKeyNegate(ctx, vn)
	if err != nil {
		return nil, err
	}
	if r != 1 {
		return nil, ErrPrivKeyNegate
	}

	if bytes.Equal(vn, result) {
		return Zero, nil
	}

	r, err = secp256k1.EcPrivKeyTweakAdd(ctx, result, vb)
	if err != nil {
		return nil, err
	}
	if r != 1 {
		return nil, ErrPrivKeyTweakAdd
	}

	return result, nil
}

// SubtractScalars subtract b from a in place
func SubtractScalars(a []byte, b []byte) ([]byte, error) {
	var aa []byte
	if a != nil {
		aa = make([]byte, len(a))
		copy(aa, a)
	}

	var bb []byte
	if b != nil {
		bb = make([]byte, len(b))
		copy(bb, b)
	}

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	if bb == nil {
		return aa, nil
	}

	r, err := secp256k1.EcPrivKeyNegate(ctx, bb)
	if err != nil {
		return nil, err
	}
	if r != 1 {
		return nil, ErrPrivKeyNegate
	}

	if aa == nil {
		return bb, nil
	}

	r, err = secp256k1.EcPrivKeyTweakAdd(ctx, aa, bb)
	if err != nil {
		return nil, err
	}
	if r != 1 {
		return nil, ErrPrivKeyTweakAdd
	}

	return a, nil
}

// ComputeAndAddToScalarOffset computes a scalar offset and adds it to another existing one
func ComputeAndAddToScalarOffset(
	scalar []byte,
	value uint64,
	assetBlinder []byte,
	valueBlinder []byte,
) ([]byte, error) {
	var s []byte
	if scalar != nil {
		s = make([]byte, len(scalar))
		copy(s, scalar)
	}

	var ab []byte
	if assetBlinder != nil {
		ab = make([]byte, len(assetBlinder))
		copy(ab, assetBlinder)
	}

	var vb []byte
	if valueBlinder != nil {
		vb = make([]byte, len(valueBlinder))
		copy(vb, valueBlinder)
	}

	// If both asset and value blinders are null, 0 is added to the offset, so nothing actually happens
	if ab == nil && vb == nil {
		return s, nil
	}

	scalarOffset, err := CalculateScalarOffset(value, ab, vb)
	if err != nil {
		return nil, err
	}

	// When we start out, the result (a) is 0, so just set it to the scalar we just computed.
	if s == nil {
		return scalarOffset, nil
	} else {
		ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
		defer secp256k1.ContextDestroy(ctx)

		var nv []byte
		if scalarOffset != nil {
			nv = make([]byte, len(scalarOffset))
			copy(nv, scalarOffset)
		}
		r, err := secp256k1.EcPrivKeyNegate(ctx, nv)
		if err != nil {
			return nil, err
		}
		if r != 1 {
			return nil, ErrPrivKeyNegate
		}

		if bytes.Equal(s, nv) {
			return Zero, nil
		}

		r, err = secp256k1.EcPrivKeyTweakAdd(ctx, s, scalarOffset)
		if err != nil {
			return nil, err
		}
		if r != 1 {
			return nil, ErrPrivKeyTweakAdd
		}
	}

	return scalar, nil
}

func CreateBlindValueProof(
	rng func() ([]byte, error),
	valueBlindingFactor []byte,
	amount uint64,
	valueCommitment []byte,
	assetCommitment []byte,
) ([]byte, error) {
	var vbf []byte
	if valueBlindingFactor != nil {
		vbf = make([]byte, len(valueBlindingFactor))
		copy(vbf, valueBlindingFactor)
	}

	var vc []byte
	if valueCommitment != nil {
		vc = make([]byte, len(valueCommitment))
		copy(vc, valueCommitment)
	}

	var ac []byte
	if assetCommitment != nil {
		ac = make([]byte, len(assetCommitment))
		copy(ac, assetCommitment)
	}

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	r, err := rng()
	if err != nil {
		return nil, err
	}

	var nonce [32]byte
	copy(nonce[:], r)

	commit, err := secp256k1.CommitmentParse(ctx, vc)
	if err != nil {
		return nil, err
	}

	gen, err := secp256k1.GeneratorParse(ctx, ac)
	if err != nil {
		return nil, err
	}

	var vbf32 [32]byte
	copy(vbf32[:], vbf)

	return secp256k1.RangeProofSign(
		ctx,
		amount,
		commit,
		vbf32,
		nonce,
		-1,
		0,
		amount,
		nil,
		nil,
		gen,
	)
}

func CreateBlindAssetProof(
	asset []byte,
	assetCommitment []byte,
	assetBlinder []byte,
) ([]byte, error) {
	var a []byte
	if asset != nil {
		a = make([]byte, len(asset))
		copy(a, asset)
	}

	var ac []byte
	if assetCommitment != nil {
		ac = make([]byte, len(assetCommitment))
		copy(ac, assetCommitment)
	}

	var ab []byte
	if assetBlinder != nil {
		ab = make([]byte, len(assetBlinder))
		copy(ab, assetBlinder)
	}

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	fixedAssetTag, err := secp256k1.FixedAssetTagParse(a)
	if err != nil {
		return nil, err
	}
	fixedInputTags := []*secp256k1.FixedAssetTag{fixedAssetTag}

	maxIterations := 100
	proof, inputIndex, err := secp256k1.SurjectionProofInitialize(
		ctx,
		fixedInputTags,
		1,
		fixedAssetTag,
		maxIterations,
		Zero,
	)
	if err != nil {
		return nil, err
	}

	gen, err := secp256k1.GeneratorGenerate(ctx, a)
	if err != nil {
		return nil, err
	}
	assetGen := []*secp256k1.Generator{gen}

	blindedAssetGen, err := secp256k1.GeneratorParse(ctx, ac)
	if err != nil {
		return nil, err
	}

	err = secp256k1.SurjectionProofGenerate(
		ctx,
		proof,
		assetGen,
		blindedAssetGen,
		inputIndex,
		Zero,
		ab,
	)
	if err != nil {
		return nil, err
	}

	if !secp256k1.SurjectionProofVerify(
		ctx,
		proof,
		assetGen,
		blindedAssetGen,
	) {
		return nil, errors.New("invalid surjection proof")
	}

	return proof.Bytes(), nil
}

func VerifyBlindValueProof(
	value int64,
	valueCommitment []byte,
	blindValueProof []byte,
	assetCommitment []byte,
) (bool, error) {
	var vc []byte
	if valueCommitment != nil {
		vc = make([]byte, len(valueCommitment))
		copy(vc, valueCommitment)
	}

	var bvp []byte
	if blindValueProof != nil {
		bvp = make([]byte, len(blindValueProof))
		copy(bvp, blindValueProof)
	}

	var ac []byte
	if assetCommitment != nil {
		ac = make([]byte, len(assetCommitment))
		copy(ac, assetCommitment)
	}

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	commitment, err := secp256k1.CommitmentParse(ctx, vc)
	if err != nil {
		return false, err
	}

	assetGenerator, err := secp256k1.GeneratorParse(ctx, ac)
	if err != nil {
		return false, err
	}

	valid, minValue, _ := secp256k1.RangeProofVerify(
		ctx,
		bvp,
		commitment,
		nil,
		assetGenerator,
	)

	return valid && int64(minValue) == value, nil
}

func VerifyBlindAssetProof(
	asset []byte,
	blindAssetProof []byte,
	assetCommitment []byte,
) (bool, error) {
	var bap []byte
	if blindAssetProof != nil {
		bap = make([]byte, len(blindAssetProof))
		copy(bap, blindAssetProof)
	}

	var ac []byte
	if assetCommitment != nil {
		ac = make([]byte, len(assetCommitment))
		copy(ac, assetCommitment)
	}

	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	surjectionProof, err := secp256k1.SurjectionProofParse(ctx, bap)
	if err != nil {
		return false, err
	}

	blindAssetGen, err := secp256k1.GeneratorParse(ctx, ac)
	if err != nil {
		return false, err
	}

	assetGen, err := secp256k1.GeneratorGenerate(ctx, asset)
	if err != nil {
		return false, err
	}
	generators := []*secp256k1.Generator{assetGen}

	if !secp256k1.SurjectionProofVerify(ctx, surjectionProof, generators, blindAssetGen) {
		return false, nil
	}

	return true, nil
}
