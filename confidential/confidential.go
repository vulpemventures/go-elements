package confidential

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-secp256k1-zkp"
)

const (
	ElementsUnconfidentialValueLength = 9
)

type UnblindOutputArg struct {
	Nonce        [32]byte
	Rangeproof   []byte
	ValueCommit  secp256k1.Commitment
	Asset        []byte
	ScriptPubkey []byte
}

type UnblindOutputResult struct {
	Value               uint64
	Asset               []byte
	ValueBlindingFactor []byte
	AssetBlindingFactor []byte
}

//NonceHash method generates hashed secret based on ecdh
func NonceHash(pubKey, privKey []byte) (
	result [32]byte,
	err error,
) {
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

//UnblindOutput method unblinds confidential transaction output
func UnblindOutput(input UnblindOutputArg) (*UnblindOutputResult, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	gen, err := secp256k1.GeneratorFromBytes(input.Asset)
	if err != nil {
		return nil, err
	}

	rewind, value, _, _, message, err := secp256k1.RangeProofRewind(
		ctx,
		&input.ValueCommit,
		input.Rangeproof,
		input.Nonce,
		input.ScriptPubkey,
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

type FinalValueBlindingFactorArg struct {
	InValues      []uint64
	OutValues     []uint64
	InGenerators  [][]byte
	OutGenerators [][]byte
	InFactors     [][]byte
	OutFactors    [][]byte
}

//FinalValueBlindingFactor method generates blind sum
func FinalValueBlindingFactor(input FinalValueBlindingFactorArg) (
	[32]byte,
	error,
) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	values := append(input.InValues, input.OutValues...)

	generatorBlind := make([][]byte, 0)
	generatorBlind = append(generatorBlind, input.InGenerators...)
	generatorBlind = append(generatorBlind, input.OutGenerators...)

	blindingFactor := make([][]byte, 0)
	blindingFactor = append(blindingFactor, input.InFactors...)
	blindingFactor = append(blindingFactor, input.OutFactors...)

	return secp256k1.BlindGeneratorBlindSum(
		ctx,
		values,
		generatorBlind,
		blindingFactor,
		len(input.InValues),
	)
}

//AssetCommitment method generates asset commitment
func AssetCommitment(asset []byte, factor []byte) (result [33]byte, err error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	generator, err := secp256k1.GeneratorGenerateBlinded(ctx, asset, factor)
	if err != nil {
		return
	}

	result = generator.Bytes()

	return
}

//ValueCommitment method generates value commitment
func ValueCommitment(value uint64, generator []byte, factor []byte) (
	result [33]byte,
	err error,
) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	gen, err := secp256k1.GeneratorParse(ctx, generator)
	if err != nil {
		return
	}

	commit, err := secp256k1.Commit(ctx, factor, value, gen)
	if err != nil {
		return
	}

	result = commit.Bytes()
	return
}

type RangeProofArg struct {
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

//RangeProof method calculates range proof
func RangeProof(input RangeProofArg) ([]byte, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	generator, err := secp256k1.GeneratorGenerateBlinded(
		ctx,
		input.Asset,
		input.AssetBlindingFactor,
	)
	if err != nil {
		return nil, err
	}

	message := append(input.Asset, input.AssetBlindingFactor...)

	commit, err := secp256k1.CommitmentParse(ctx, input.ValueCommit)
	if err != nil {
		return nil, err
	}

	var mv uint64
	if input.MinValue > 0 {
		mv = input.MinValue
	} else {
		mv = 1
	}

	var e int
	if input.MinValue > 0 {
		e = input.Exp
	} else {
		e = 1
	}

	var mb int
	if input.MinBits > 0 {
		mb = input.MinBits
	} else {
		mb = 36
	}

	return secp256k1.RangeProofSign(
		ctx,
		mv,
		commit,
		input.ValueBlindFactor,
		input.Nonce,
		e,
		mb,
		input.Value,
		message,
		input.ScriptPubkey,
		generator,
	)
}

type SurjectionProofArg struct {
	OutputAsset               []byte
	OutputAssetBlindingFactor []byte
	InputAssets               [][]byte
	InputAssetBlindingFactors [][]byte
	Seed                      []byte
}

//SurjectionProof method generates surjection proof
func SurjectionProof(input SurjectionProofArg) ([]byte, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	outputGenerator, err := secp256k1.GeneratorGenerateBlinded(
		ctx,
		input.OutputAsset,
		input.OutputAssetBlindingFactor,
	)
	if err != nil {
		return nil, err
	}

	inputGenerators := make([]secp256k1.Generator, 0)
	for i, v := range input.InputAssets {
		gen, err := secp256k1.GeneratorGenerateBlinded(
			ctx,
			v,
			input.InputAssetBlindingFactors[i],
		)
		if err != nil {
			return nil, err
		}
		inputGenerators = append(inputGenerators, *gen)
	}

	fixedInputTags := make([]secp256k1.FixedAssetTag, 0)
	for _, inTag := range input.InputAssets {
		fixedAssetTag, err := secp256k1.FixedAssetTagParse(inTag)
		if err != nil {
			return nil, err
		}
		fixedInputTags = append(fixedInputTags, *fixedAssetTag)
	}

	var nInputsToUse int
	if len(input.InputAssets) > 3 {
		nInputsToUse = 3
	} else {
		nInputsToUse = len(input.InputAssets)
	}

	fixedOutputTag, err := secp256k1.FixedAssetTagParse(input.OutputAsset)
	if err != nil {
		return nil, err
	}

	maxIterations := 100
	proof, inputIndex, err := secp256k1.SurjectionProofInitialize(
		ctx,
		fixedInputTags,
		nInputsToUse,
		*fixedOutputTag,
		maxIterations,
		input.Seed,
	)
	if err != nil {
		return nil, err
	}

	err = secp256k1.SurjectionProofGenerate(
		ctx,
		proof,
		inputGenerators,
		*outputGenerator,
		inputIndex,
		input.InputAssetBlindingFactors[inputIndex],
		input.OutputAssetBlindingFactor)
	if err != nil {
		return nil, err
	}

	return secp256k1.SurjectionProofSerialize(ctx, proof)
}

//SatoshiToElementsValue method converts Satoshi value to Elements value
func SatoshiToElementsValue(val uint64) (
	result [ElementsUnconfidentialValueLength]byte,
	err error,
) {
	unconfPrefix := byte(1)
	b := bytes.NewBuffer([]byte{})
	if err = bufferutil.BinarySerializer.PutUint64(
		b,
		binary.LittleEndian,
		val,
	); err != nil {
		return
	}
	copy(
		result[:],
		append([]byte{unconfPrefix}, bufferutil.ReverseBytes(b.Bytes())...),
	)

	return
}

//ElementsToSatoshiValue method converts Elements value to Satoshi value
func ElementsToSatoshiValue(val [ElementsUnconfidentialValueLength]byte) (
	result uint64,
	err error,
) {
	if val[0] != byte(1) {
		err = errors.New("invalid prefix")
		return
	}
	reverseValueBuffer := [ElementsUnconfidentialValueLength - 1]byte{}
	copy(reverseValueBuffer[:], val[1:])
	bufferutil.ReverseBytes(reverseValueBuffer[:])
	d := bufferutil.NewDeserializer(bytes.NewBuffer(reverseValueBuffer[:]))
	result, err = d.ReadUint64()
	return
}

// CommitmentFromBytes parses a raw commitment.
// This should be moved into go-secp256k1-zkp library, check out
// https://github.com/vulpemventures/go-elements/pull/79#discussion_r435315406
func CommitmentFromBytes(commit []byte) (*secp256k1.Commitment, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)
	return secp256k1.CommitmentParse(ctx, commit)
}
