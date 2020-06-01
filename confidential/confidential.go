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
func NonceHash(ctx *secp256k1.Context, pubKey, privKey []byte) (result [32]byte, err error) {
	_, publicKey, err := secp256k1.EcPubkeyParse(ctx, pubKey)
	if err != nil {
		return result, err
	}

	_, ecdh, err := secp256k1.Ecdh(ctx, publicKey, privKey)
	if err != nil {
		return result, err
	}

	result = sha256.Sum256(ecdh)
	return result, nil
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

	rewind, value, _, _, message, err := secp256k1.RangeProofRewind(ctx, &input.ValueCommit, input.Rangeproof, nonce, input.ScriptPubkey, gen)
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

//AssetCommitment method generates asset commitment
func AssetCommitment(asset []byte, factor []byte) (result [33]byte, err error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	generator, err := secp256k1.GeneratorGenerateBlinded(ctx, asset, factor)
	if err != nil {
		return result, err
	}

	result = generator.Bytes()

	return result, nil
}

//ValueCommitment method generates value commitment
func ValueCommitment(value uint64, generator []byte, factor []byte) (result [33]byte, err error) {
	ctx, _ := secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(ctx)

	gen, err := secp256k1.GeneratorParse(ctx, generator)
	if err != nil {
		return result, err
	}

	commit, err := secp256k1.Commit(ctx, factor, value, gen)
	if err != nil {
		return result, err
	}

	return commit.Bytes(), nil
}
