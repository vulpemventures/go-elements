package transaction

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
func NonceHash(ctx *secp256k1.Context, pubKey *secp256k1.PublicKey, privKey []byte) (*[32]byte, error) {
	_, ecdh, err := secp256k1.Ecdh(ctx, pubKey, privKey)
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

	_, pubKey, err := secp256k1.EcPubkeyParse(ctx, input.EphemeralPubkey)
	if err != nil {
		return nil, err
	}

	gen, err := secp256k1.GeneratorFromBytes(input.Asset)
	if err != nil {
		return nil, err
	}

	nonce, err := NonceHash(ctx, pubKey, input.BlindingPrivkey)
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
