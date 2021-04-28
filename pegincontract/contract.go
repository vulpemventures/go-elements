package pegincontract

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-secp256k1-zkp"
)

const (
	pubKeyLen = 33
)

func Calculate(
	federationScript []byte,
	scriptPubKey []byte,
) ([]byte, error) {
	contract := make([]byte, 0)

	ctx, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		return nil, err
	}

	isLiquidV1Watchman, err := IsLiquidV1(federationScript)
	if err != nil {
		return nil, err
	}

	pops, err := address.ParseScript(
		federationScript,
	)
	if err != nil {
		return nil, err
	}

	liquidOpElseFound := false
	for _, v := range pops {
		// For liquidv1 initial watchman template, don't tweak emergency keys
		if isLiquidV1Watchman && v.Opcode.Value == address.OP_ELSE {
			liquidOpElseFound = true
		}

		if len(v.Data) == pubKeyLen && !liquidOpElseFound {
			mac := hmac.New(sha256.New, v.Data)
			mac.Write(scriptPubKey)
			tweak := mac.Sum(nil)

			_, watchman, err := secp256k1.EcPubkeyParse(ctx, v.Data)
			if err != nil {
				return nil, err
			}

			_, tweaked, err := secp256k1.EcPubkeyParse(ctx, v.Data)
			if err != nil {
				return nil, err
			}

			_, err = secp256k1.EcPubKeyTweakAdd(ctx, tweaked, tweak)
			if err != nil {
				return nil, err
			}

			_, newPub, err := secp256k1.EcPubkeySerialize(
				ctx,
				tweaked,
				secp256k1.EcCompressed,
			)

			contract = append(contract, byte(len(newPub)))
			contract = append(contract, newPub...)

			// Sanity checks to reduce pegin risk. If the tweaked
			// value flips a bit, we may lose pegin funds irretrievably.
			// We take the tweak, derive its pubkey and check that
			// `tweaked - watchman = tweak` to check the computation
			// two different ways
			_, tweaked2, err := secp256k1.EcPubkeyCreate(ctx, tweak)
			if err != nil {
				return nil, err
			}

			_, err = secp256k1.EcPubKeyNegate(ctx, watchman)
			if err != nil {
				return nil, err
			}

			vPoint := []*secp256k1.PublicKey{watchman, tweaked}
			_, maybeTweaked2, err := secp256k1.EcPubKeyCombine(ctx, vPoint)
			if err != nil {
				return nil, err
			}

			_, tweaked2Bytes, err := secp256k1.EcPubkeySerialize(
				ctx,
				tweaked2,
				secp256k1.EcUncompressed,
			)

			_, maybeTweaked2Bytes, err := secp256k1.EcPubkeySerialize(
				ctx,
				maybeTweaked2,
				secp256k1.EcUncompressed,
			)

			if !bytes.Equal(tweaked2Bytes[:64], maybeTweaked2Bytes[:64]) {
				return nil, errors.New("sanity check failed")
			}

		} else {
			if len(v.Data) > 0 {
				contract = append(contract, byte(len(v.Data)))
				contract = append(contract, v.Data...)
			} else {
				contract = append(contract, v.Opcode.Value)
			}
		}

	}

	return contract, nil
}

// IsLiquidV1 checks weather provided fedpeg script is of v1 or newer
// Consensus-critical. Matching against telescoped multisig used on Liquid v1
func IsLiquidV1(script []byte) (bool, error) {
	pops, err := address.ParseScript(script)
	if err != nil {
		return false, err
	}

	// Stack depth check for branch choice
	if pops[0].Opcode.Value != address.OP_DEPTH {
		return false, nil
	}

	// Take in value, then check equality
	if pops[2].Opcode.Value != address.OP_EQUAL {
		return false, nil
	}

	// IF EQUAL
	if pops[3].Opcode.Value != address.OP_IF {
		return false, nil
	}

	// Take in value k, make sure minimally encoded number from 1 to 16
	if pops[4].Opcode.Value > address.OP_16 ||
		(pops[4].Opcode.Value < address.OP_1NEGATE && !checkMinimalPush(pops[4])) {

		return false, nil
	}

	// Iterate through multisig stuff until ELSE is hit
	opElseFound := false
	opElseIndex := -1
	for i := 5; i < len(pops); i++ {
		if pops[i].Opcode.Value == address.OP_ELSE {
			opElseFound = true
			opElseIndex = i
		}
	}
	if !opElseFound {
		return false, err
	}

	// Take minimally-encoded CSV push number k'
	if pops[opElseIndex+1].Opcode.Value > address.OP_16 ||
		(pops[opElseIndex+1].Opcode.Value < address.OP_1NEGATE && !checkMinimalPush(pops[opElseIndex+1])) {

		return false, nil
	}

	// CSV
	if pops[opElseIndex+2].Opcode.Value != address.OP_CHECKSEQUENCEVERIFY {
		return false, nil
	}

	// Drop the CSV number
	if pops[opElseIndex+3].Opcode.Value != address.OP_DROP {
		return false, nil
	}

	// Take the minimally-encoded n of k-of-n multisig arg
	if pops[opElseIndex+4].Opcode.Value > address.OP_16 ||
		(pops[opElseIndex+4].Opcode.Value < address.OP_1NEGATE && !checkMinimalPush(pops[opElseIndex+4])) {

		return false, nil
	}

	// Iterate through multisig stuff until ENDIF is hit
	opEndIfFound := false
	opEndIfIndex := -1
	for i := opElseIndex + 5; i < len(pops); i++ {
		if pops[i].Opcode.Value == address.OP_ENDIF {
			opEndIfFound = true
			opEndIfIndex = i
		}
	}
	if !opEndIfFound {
		return false, err
	}

	// CHECKMULTISIG
	if pops[opEndIfIndex+1].Opcode.Value != address.OP_CHECKMULTISIG {
		return false, nil
	}

	return true, err
}

func checkMinimalPush(parsedOpcode address.ParsedOpcode) bool {
	if len(parsedOpcode.Data) == 0 {
		// Should have used OP_0.
		return parsedOpcode.Opcode.Value == address.OP_0
	} else if len(parsedOpcode.Data) == 1 &&
		parsedOpcode.Data[0] >= 1 &&
		parsedOpcode.Data[0] <= 16 {
		// Should have used OP_1 .. OP_16.
		return false
	} else if len(parsedOpcode.Data) == 1 && parsedOpcode.Data[0] == 0x81 {
		// Should have used OP_1NEGATE.
		return false
	} else if len(parsedOpcode.Data) <= 75 {
		// Must have used a direct push (opcode indicating number of bytes pushed + those bytes).
		return int(parsedOpcode.Opcode.Value) == len(parsedOpcode.Data)
	} else if len(parsedOpcode.Data) <= 255 {
		// Must have used OP_PUSHDATA.
		return int(parsedOpcode.Opcode.Value) == address.OP_PUSHDATA1
	} else if len(parsedOpcode.Data) <= 65535 {
		// Must have used OP_PUSHDATA2.
		return int(parsedOpcode.Opcode.Value) == address.OP_PUSHDATA2
	}
	return true
}
