package address

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
)

// ScriptClass is an enumeration for the list of standard types of script.
type ScriptClass byte

// Classes of script payment known about in the blockchain.
const (
	NonStandardTy         ScriptClass = iota // None of the recognized forms.
	PubKeyTy                                 // Pay pubkey.
	PubKeyHashTy                             // Pay pubkey hash.
	WitnessV0PubKeyHashTy                    // Pay witness pubkey hash.
	ScriptHashTy                             // Pay to script hash.
	WitnessV0ScriptHashTy                    // Pay to witness script hash.
	MultiSigTy                               // Multi signature.
	NullDataTy                               // Empty Data-only (provably prunable).
)

const (
	// MaxDataCarrierSize is the maximum number of bytes allowed in pushed
	// Data to be considered a nulldata transaction
	MaxDataCarrierSize = 80
)

// parseScript preparses the script in bytes into a list of parsedOpcodes while
// applying a number of sanity checks.
func ParseScript(script []byte) ([]ParsedOpcode, error) {
	return parseScriptTemplate(script, &opcodeArray)
}

// scriptType returns the type of the script being inspected from the known
// standard types.
func TypeOfScript(pops []ParsedOpcode) ScriptClass {
	if IsPubkey(pops) {
		return PubKeyTy
	} else if IsPubkeyHash(pops) {
		return PubKeyHashTy
	} else if IsWitnessPubKeyHash(pops) {
		return WitnessV0PubKeyHashTy
	} else if IsScriptHash(pops) {
		return ScriptHashTy
	} else if IsWitnessScriptHash(pops) {
		return WitnessV0ScriptHashTy
	} else if IsMultiSig(pops) {
		return MultiSigTy
	} else if isNullData(pops) {
		return NullDataTy
	}
	return NonStandardTy
}

// IsPubkey returns true if the script passed is a pay-to-pubkey transaction,
// false otherwise.
func IsPubkey(pops []ParsedOpcode) bool {
	// Valid pubkeys are either 33 or 65 bytes.
	return len(pops) == 2 &&
		(len(pops[0].Data) == 33 || len(pops[0].Data) == 65) &&
		pops[1].Opcode.Value == txscript.OP_CHECKSIG
}

// IsPubkeyHash returns true if the script passed is a pay-to-pubkey-hash
// transaction, false otherwise.
func IsPubkeyHash(pops []ParsedOpcode) bool {
	return len(pops) == 5 &&
		pops[0].Opcode.Value == txscript.OP_DUP &&
		pops[1].Opcode.Value == txscript.OP_HASH160 &&
		pops[2].Opcode.Value == txscript.OP_DATA_20 &&
		pops[3].Opcode.Value == txscript.OP_EQUALVERIFY &&
		pops[4].Opcode.Value == txscript.OP_CHECKSIG

}

// IsMultiSig returns true if the passed script is a multisig transaction, false
// otherwise.
func IsMultiSig(pops []ParsedOpcode) bool {
	// The absolute minimum is 1 pubkey:
	// OP_0/OP_1-16 <pubkey> OP_1 OP_CHECKMULTISIG
	l := len(pops)
	if l < 4 {
		return false
	}
	if !isSmallInt(pops[0].Opcode) {
		return false
	}
	if !isSmallInt(pops[l-2].Opcode) {
		return false
	}
	if pops[l-1].Opcode.Value != txscript.OP_CHECKMULTISIG {
		return false
	}

	// Verify the number of pubkeys specified matches the actual number
	// of pubkeys provided.
	if l-2-1 != asSmallInt(pops[l-2].Opcode) {
		return false
	}

	for _, pop := range pops[1 : l-2] {
		// Valid pubkeys are either 33 or 65 bytes.
		if len(pop.Data) != 33 && len(pop.Data) != 65 {
			return false
		}
	}
	return true
}

// IsWitnessPubKeyHash returns true if the passed script is a
// pay-to-witness-pubkey-hash, and false otherwise.
func IsWitnessPubKeyHash(pops []ParsedOpcode) bool {
	return len(pops) == 2 &&
		pops[0].Opcode.Value == txscript.OP_0 &&
		pops[1].Opcode.Value == txscript.OP_DATA_20
}

// isSmallInt returns whether or not the Opcode is considered a small integer,
// which is an OP_0, or OP_1 through OP_16.
func isSmallInt(op *Opcode) bool {
	if op.Value == txscript.OP_0 || (op.Value >= txscript.OP_1 && op.Value <= txscript.OP_16) {
		return true
	}
	return false
}

// IsScriptHash returns true if the script passed is a pay-to-script-hash
// transaction, false otherwise.
func IsScriptHash(pops []ParsedOpcode) bool {
	return len(pops) == 3 &&
		pops[0].Opcode.Value == txscript.OP_HASH160 &&
		pops[1].Opcode.Value == txscript.OP_DATA_20 &&
		pops[2].Opcode.Value == txscript.OP_EQUAL
}

// IsWitnessScriptHash returns true if the passed script is a
// pay-to-witness-script-hash transaction, false otherwise.
func IsWitnessScriptHash(pops []ParsedOpcode) bool {
	return len(pops) == 2 &&
		pops[0].Opcode.Value == txscript.OP_0 &&
		pops[1].Opcode.Value == txscript.OP_DATA_32
}

// isNullData returns true if the passed script is a null Data transaction,
// false otherwise.
func isNullData(pops []ParsedOpcode) bool {
	// A nulldata transaction is either a single OP_RETURN or an
	// OP_RETURN SMALLDATA (where SMALLDATA is a Data push up to
	// MaxDataCarrierSize bytes).
	l := len(pops)
	if l == 1 && pops[0].Opcode.Value == txscript.OP_RETURN {
		return true
	}

	return l == 2 &&
		pops[0].Opcode.Value == txscript.OP_RETURN &&
		(isSmallInt(pops[1].Opcode) || pops[1].Opcode.Value <=
			txscript.OP_PUSHDATA4) &&
		len(pops[1].Data) <= MaxDataCarrierSize
}

// asSmallInt returns the passed Opcode, which must be true according to
// isSmallInt(), as an integer.
func asSmallInt(op *Opcode) int {
	if op.Value == txscript.OP_0 {
		return 0
	}

	return int(op.Value - (txscript.OP_1 - 1))
}

// parseScriptTemplate is the same as parseScript but allows the passing of the
// template list for testing purposes.  When there are parse errors, it returns
// the list of parsed opcodes up to the point of failure along with the error.
func parseScriptTemplate(script []byte, opcodes *[256]Opcode) ([]ParsedOpcode, error) {
	retScript := make([]ParsedOpcode, 0, len(script))
	for i := 0; i < len(script); {
		instr := script[i]
		op := &opcodes[instr]
		pop := ParsedOpcode{Opcode: op}

		// Parse Data out of instruction.
		switch {
		// No additional Data.  Note that some of the opcodes, notably
		// OP_1NEGATE, OP_0, and OP_[1-16] represent the Data
		// themselves.
		case op.Length == 1:
			i++

		// Data pushes of specific lengths -- OP_DATA_[1-75].
		case op.Length > 1:
			if len(script[i:]) < op.Length {
				str := fmt.Sprintf("Opcode %s requires %d "+
					"bytes, but script only has %d remaining",
					op.Name, op.Length, len(script[i:]))
				return nil, errors.New(str)
			}

			// Slice out the Data.
			pop.Data = script[i+1 : i+op.Length]
			i += op.Length

		// Data pushes with parsed lengths -- OP_PUSHDATAP{1,2,4}.
		case op.Length < 0:
			var l uint
			off := i + 1

			if len(script[off:]) < -op.Length {
				str := fmt.Sprintf("Opcode %s requires %d "+
					"bytes, but script only has %d remaining",
					op.Name, -op.Length, len(script[off:]))
				return nil, errors.New(str)
			}

			// Next -Length bytes are little endian Length of Data.
			switch op.Length {
			case -1:
				l = uint(script[off])
			case -2:
				l = (uint(script[off+1]) << 8) |
					uint(script[off])
			case -4:
				l = (uint(script[off+3]) << 24) |
					(uint(script[off+2]) << 16) |
					(uint(script[off+1]) << 8) |
					uint(script[off])
			default:
				str := fmt.Sprintf("invalid Opcode Length %d",
					op.Length)
				return nil, errors.New(str)
			}

			// Move offset to beginning of the Data.
			off += -op.Length

			// Disallow entries that do not fit script or were
			// sign extended.
			if int(l) > len(script[off:]) || int(l) < 0 {
				str := fmt.Sprintf("Opcode %s pushes %d bytes, "+
					"but script only has %d remaining",
					op.Name, int(l), len(script[off:]))
				return nil, errors.New(str)
			}

			pop.Data = script[off : off+int(l)]
			i += 1 - op.Length + int(l)
		}

		retScript = append(retScript, pop)
	}

	return retScript, nil
}
