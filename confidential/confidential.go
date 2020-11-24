package confidential

import (
	"crypto/sha256"
	"errors"

	"github.com/vulpemventures/go-elements/transaction"
	"github.com/vulpemventures/go-secp256k1-zkp"
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
	return rangeProof(args)
}

type SurjectionProofArgs struct {
	OutputAsset               []byte
	OutputAssetBlindingFactor []byte
	InputAssets               [][]byte
	InputAssetBlindingFactors [][]byte
	Seed                      []byte
}

func (a SurjectionProofArgs) nInputsToUse() int {
	if len(a.InputAssets) >= 3 {
		return 3
	}
	return len(a.InputAssets)
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
		*fixedOutputTag,
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
		*outputGenerator,
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
		*outputGenerator,
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
		*outGenerator,
	)
}

func inAssetGenerators(inAssets, inAssetBlinders [][]byte) ([]secp256k1.Generator, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	inGenerators := make([]secp256k1.Generator, 0, len(inAssets))
	for i, inAsset := range inAssets {
		gen, err := secp256k1.GeneratorGenerateBlinded(
			ctx,
			inAsset,
			inAssetBlinders[i],
		)
		if err != nil {
			return nil, err
		}
		inGenerators = append(inGenerators, *gen)
	}
	return inGenerators, nil
}

func outAssetGenerator(outAsset, outAssetBlinder []byte) (*secp256k1.Generator, error) {
	res, err := inAssetGenerators([][]byte{outAsset}, [][]byte{outAssetBlinder})
	if err != nil {
		return nil, err
	}
	outGenerator := res[0]
	return &outGenerator, nil
}

func inFixedTags(inAssets [][]byte) ([]secp256k1.FixedAssetTag, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	fixedInputTags := make([]secp256k1.FixedAssetTag, 0, len(inAssets))
	for _, inTag := range inAssets {
		fixedAssetTag, err := secp256k1.FixedAssetTagParse(inTag)
		if err != nil {
			return nil, err
		}
		fixedInputTags = append(fixedInputTags, *fixedAssetTag)
	}
	return fixedInputTags, nil
}

func outFixedTag(outAsset []byte) (*secp256k1.FixedAssetTag, error) {
	res, err := inFixedTags([][]byte{outAsset})
	if err != nil {
		return nil, err
	}
	outFixedTag := res[0]
	return &outFixedTag, nil
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
