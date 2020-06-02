package confidential

import (
	"crypto/sha256"
	"github.com/vulpemventures/go-secp256k1-zkp"
)

type UnblindInput struct {
	EphemeralPubkey []byte
	BlindingPrivkey []byte
	Rangeproof      []byte
	ValueCommit     secp256k1.Commitment
	Asset           []byte
	ScriptPubkey    []byte
}

type UnblindOutputResult struct {
	Value               uint64
	Asset               []byte
	ValueBlindingFactor []byte
	AssetBlindingFactor []byte
}

//NonceHash method generates hashed secret based on ecdh
func NonceHash(ctx *secp256k1.Context, pubKey, privKey []byte) (*[32]byte, error) {
	_, publicKey, err := secp256k1.EcPubkeyParse(ctx, pubKey)
	if err != nil {
		return nil, err
	}

	_, ecdh, err := secp256k1.Ecdh(ctx, publicKey, privKey)
	if err != nil {
		return nil, err
	}

	result := sha256.Sum256(ecdh)
	return &result, nil
}

//UnblindOutput method unblinds confidential transaction output
func UnblindOutput(input UnblindInput) (*UnblindOutputResult, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	gen, err := secp256k1.GeneratorFromBytes(input.Asset)
	if err != nil {
		return nil, err
	}

	nonce, err := NonceHash(ctx, input.EphemeralPubkey, input.BlindingPrivkey)
	if err != nil {
		return nil, err
	}

	rewind, value, _, _, message, err := secp256k1.RangeProofRewind(ctx, &input.ValueCommit, input.Rangeproof, *nonce, input.ScriptPubkey, gen)
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

type FinalValueBlindingFactorInput struct {
	InValues      []uint64
	OutValues     []uint64
	InGenerators  [][]byte
	OutGenerators [][]byte
	InFactors     [][]byte
	OutFactors    [][]byte
}

//FinalValueBlindingFactor method generates blind sum
func FinalValueBlindingFactor(input FinalValueBlindingFactorInput) ([32]byte, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	values := append(input.InValues, input.OutValues...)

	generatorBlind := make([][]byte, 0)
	generatorBlind = append(generatorBlind, input.InGenerators...)
	generatorBlind = append(generatorBlind, input.OutGenerators...)

	blindingFactor := make([][]byte, 0)
	blindingFactor = append(blindingFactor, input.InFactors...)
	blindingFactor = append(blindingFactor, input.OutFactors...)

	return secp256k1.BlindGeneratorBlindSum(ctx, values, generatorBlind, blindingFactor, len(input.InValues))
}

type SurjectionProofInput struct {
	OutputAsset               []byte
	OutputAssetBlindingFactor []byte
	InputAssets               [][]byte
	InputAssetBlindingFactors [][]byte
	Seed                      []byte
}

//SurjectionProof method generates surjection proof
func SurjectionProof(input SurjectionProofInput) ([]byte, error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	outputGenerator, err := secp256k1.GeneratorGenerateBlinded(ctx, input.OutputAsset, input.OutputAssetBlindingFactor)
	if err != nil {
		return nil, err
	}

	inputGenerators := make([]secp256k1.Generator, 0)
	for i, v := range input.InputAssets {
		gen, err := secp256k1.GeneratorGenerateBlinded(ctx, v, input.InputAssetBlindingFactors[i])
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
	proof, inputIndex, err := secp256k1.SurjectionProofInitialize(ctx, fixedInputTags, nInputsToUse, *fixedOutputTag, maxIterations, input.Seed)
	if err != nil {
		return nil, err
	}

	err = secp256k1.SurjectionProofGenerate(ctx, proof, inputGenerators, *outputGenerator, inputIndex, input.InputAssetBlindingFactors[inputIndex], input.OutputAssetBlindingFactor)
	if err != nil {
		return nil, err
	}

	return secp256k1.SurjectionProofSerialize(ctx, proof)
}
