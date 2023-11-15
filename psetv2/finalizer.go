// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psetv2

// The Finalizer requires provision of a single PSET input
// in which all necessary signatures are encoded, and
// uses it to construct valid final sigScript and scriptWitness
// fields.
// NOTE that p2sh (legacy) and p2wsh currently support only
// multisig and no other custom script.

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

var (
	ErrFinalizerInvalidSigHashFlags   = fmt.Errorf("invalid sighash flags")
	ErrFinalizerForbiddenFinalization = fmt.Errorf("pset is not finalizable")
	ErrFinalizerAlreadyFinalized      = fmt.Errorf(
		"cannot finalize pset, finalized scriptSig or scriptWitnes already exists",
	)
)

// FinalizeAll finalizes all inputs of a partial elements transaction by
// calling the Finalize function for every partial input
func FinalizeAll(p *Pset) error {
	pp := p.Copy()

	for inIndex := range p.Inputs {
		if err := Finalize(pp, inIndex); err != nil {
			return err
		}
	}

	p.Global = pp.Global
	p.Inputs = pp.Inputs
	p.Outputs = pp.Outputs
	return nil
}

// Finalize assumes that the provided pset.Pset struct has all partial
// signatures and redeem scripts/witness scripts already prepared for the
// specified input, and so removes all temporary data and replaces them with
// completed sigScript and witness fields, which are stored in key-types 07 and
// 08. The witness/non-witness utxo fields in the inputs (key-types 00 and 01)
// are left intact as they may be needed for validation (?).  If there is any
// invalid or incomplete data, an error is returned.
func Finalize(p *Pset, inIndex int) error {
	input := p.Inputs[inIndex]

	// Depending on the UTXO type, we either attempt to finalize it as a
	// witness or legacy UTXO.
	switch {
	case input.WitnessUtxo != nil:
		if input.isTaproot() {
			return finalizeTaprootInput(p, inIndex)
		}

		if err := finalizeWitnessInput(p, inIndex); err != nil {
			return err
		}
	case input.NonWitnessUtxo != nil:
		if err := finalizeNonWitnessInput(p, inIndex); err != nil {
			return err
		}
	default:
		return ErrInvalidPsbtFormat
	}

	p.Inputs[inIndex].PartialSigs = nil

	// Before returning we sanity check the PSET to ensure we don't extract
	// an invalid transaction or produce an invalid intermediate state.
	return p.SanityCheck()
}

// MaybeFinalizeAll attempts to finalize all inputs of the pset.Pset that are
// not already finalized, and returns an error if it fails to do so.
func MaybeFinalizeAll(p *Pset) error {
	for i := range p.Inputs {
		success, err := MaybeFinalize(p, i)
		if err != nil || !success {
			return err
		}
	}

	return nil
}

// MaybeFinalize attempts to finalize the input at index inIndex in the PSET p,
// returning true with no error if it succeeds, OR if the input has already
// been finalized.
func MaybeFinalize(p *Pset, inIndex int) (bool, error) {
	if isFinalized(p, inIndex) {
		return true, nil
	}

	if !isFinalizable(p, inIndex) {
		return false, ErrFinalizerForbiddenFinalization
	}

	if err := Finalize(p, inIndex); err != nil {
		return false, err
	}

	return true, nil
}

// isFinalized considers this input finalized if it contains at least one of
// the FinalScriptSig or FinalScriptWitness are filled (which only occurs in a
// successful call to Finalize*).
func isFinalized(p *Pset, inIndex int) bool {
	input := p.Inputs[inIndex]
	return len(input.FinalScriptSig) > 0 || len(input.FinalScriptWitness) > 0
}

// isFinalizableWitnessInput returns true if the target input is a witness UTXO
// that can be finalized.
func isFinalizableWitnessInput(input *Input) bool {
	pkScript := input.WitnessUtxo.Script

	switch {
	// If this is a native witness output, then we require both
	// the witness script, but not a redeem script.
	case txscript.IsWitnessProgram(pkScript):
		if txscript.IsPayToWitnessScriptHash(pkScript) {
			if len(input.WitnessScript) == 0 ||
				len(input.RedeemScript) > 0 {
				return false
			}
		} else if txscript.IsPayToTaproot(pkScript) {
			if len(input.TapKeySig) > 0 {
				return true
			}

			for _, sig := range input.TapScriptSig {
				hasTapLeafScript := false
				for _, tapLeaf := range input.TapLeafScript {
					h := tapLeaf.TapHash()
					if bytes.Equal(sig.LeafHash, h[:]) {
						hasTapLeafScript = true
						break
					}
				}
				if !hasTapLeafScript {
					return false
				}
			}
			return true
		} else {
			// A P2WKH output on the other hand doesn't need
			// neither a witnessScript or redeemScript.
			if len(input.WitnessScript) > 0 ||
				len(input.RedeemScript) > 0 {
				return false
			}
		}

	// For nested P2SH inputs, we verify that a witness script is known.
	case txscript.IsPayToScriptHash(pkScript):
		if len(input.RedeemScript) == 0 {
			return false
		}

		// If this is a nested P2SH input, then it must also have a
		// witness script, while we don't need one for P2WKH.
		if txscript.IsPayToWitnessScriptHash(input.RedeemScript) {
			if len(input.WitnessScript) == 0 {
				return false
			}
		} else if txscript.IsPayToWitnessPubKeyHash(input.RedeemScript) {
			if len(input.WitnessScript) > 0 {
				return false
			}
		} else {
			// unrecognized type
			return false
		}

	// If this isn't a nested nested P2SH output or a native witness
	// output, then we can't finalize this input as we don't understand it.
	default:
		return false
	}

	return true
}

// isFinalizableLegacyInput returns true of the passed input a legacy input
// (non-witness) that can be finalized.
func isFinalizableLegacyInput(p *Pset, input *Input, inIndex int) bool {
	// If the input has a witness, then it's invalid.
	if len(input.WitnessScript) > 0 {
		return false
	}

	// Otherwise, we'll verify that we only have a RedeemScript if the prev
	// output script is P2SH.
	outIndex := p.Inputs[inIndex].PreviousTxIndex
	if txscript.IsPayToScriptHash(input.NonWitnessUtxo.Outputs[outIndex].Script) {
		if len(input.RedeemScript) == 0 {
			return false
		}
	} else {
		if len(input.RedeemScript) > 0 {
			return false
		}
	}

	return true
}

// isFinalizable checks whether the structure of the entry for the input of the
// pset.Pset at index inIndex contains sufficient information to finalize
// this input.
func isFinalizable(p *Pset, inIndex int) bool {
	input := p.Inputs[inIndex]

	// The input cannot be finalized without any signatures
	if len(input.PartialSigs) == 0 {
		return false
	}

	// For an input to be finalized, we'll one of two possible top-level
	// UTXOs present. Each UTXO type has a distinct set of requirements to
	// be considered finalized.
	switch {
	// A witness input must be either native P2WSH or nested P2SH with all
	// relevant sigScript or witness data populated.
	case input.WitnessUtxo != nil:
		if !isFinalizableWitnessInput(&input) {
			return false
		}

	case input.NonWitnessUtxo != nil:
		if !isFinalizableLegacyInput(p, &input, inIndex) {
			return false
		}

	// If neither a known UTXO type isn't present at all, then we'll
	// return false as we need one of them.
	default:
		return false
	}

	return true
}

// checkFinalScriptSigWitness checks whether a given input in the pset.Pset
// struct already has the fields 07 (FinalInScriptSig) or 08 (FinalInWitness).
// If so, it returns true. It does not modify the Pset.
func checkFinalScriptSigWitness(p *Pset, inIndex int) bool {
	input := p.Inputs[inIndex]

	if len(input.FinalScriptSig) > 0 {
		return true
	}

	if len(input.FinalScriptWitness) > 0 {
		return true
	}

	return false
}

// finalizeNonWitnessInput attempts to create a PsetInFinalScriptSig field for
// the input at index inIndex, and removes all other fields except for the UTXO
// field, for an input of type non-witness, or returns an error.
func finalizeNonWitnessInput(p *Pset, inIndex int) error {
	// If this input has already been finalized, then we'll return an error
	// as we can't proceed.
	if checkFinalScriptSigWitness(p, inIndex) {
		return ErrFinalizerAlreadyFinalized
	}

	// Our goal here is to construct a sigScript given the pubkey,
	// signature (keytype 02), of which there might be multiple, and the
	// redeem script field (keytype 04) if present (note, it is not present
	// for p2pkh type inputs).
	var sigScript []byte

	input := p.Inputs[inIndex]
	containsRedeemScript := len(input.RedeemScript) > 0

	var (
		pubKeys [][]byte
		sigs    [][]byte
	)
	for _, ps := range input.PartialSigs {
		pubKeys = append(pubKeys, ps.PubKey)

		sigOK := checkSigHashFlags(ps.Signature, input)
		if !sigOK {
			return ErrFinalizerInvalidSigHashFlags
		}

		sigs = append(sigs, ps.Signature)
	}

	// We have failed to identify at least 1 (sig, pub) pair in the PSET,
	// which indicates it was not ready to be finalized. As a result, we
	// can't proceed.
	if len(sigs) < 1 || len(pubKeys) < 1 {
		return ErrFinalizerForbiddenFinalization
	}

	// If this input doesn't need a redeem script (P2PKH), then we'll
	// construct a simple sigScript that's just the signature then the
	// pubkey (OP_CHECKSIG).
	var err error
	if !containsRedeemScript {
		// At this point, we should only have a single signature and
		// pubkey.
		if len(sigs) != 1 || len(pubKeys) != 1 {
			return ErrFinalizerForbiddenFinalization
		}

		// In this case, our sigScript is just: <sig> <pubkey>.
		builder := txscript.NewScriptBuilder()
		builder.AddData(sigs[0]).AddData(pubKeys[0])
		sigScript, err = builder.Script()
		if err != nil {
			return err
		}
	} else {
		// This is assumed p2sh multisig Given redeemScript and pubKeys
		// we can decide in what order signatures must be appended.
		orderedSigs, err := extractKeyOrderFromScript(
			input.RedeemScript, pubKeys, sigs,
		)
		if err != nil {
			return err
		}

		// At this point, we assume that this is a mult-sig input, so
		// we construct our sigScript which looks something like this
		// (mind the extra element for the extra multi-sig pop):
		//  * <nil> <sigs...> <redeemScript>
		//
		// TODO(waxwing): the below is specific to the multisig case.
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		for _, os := range orderedSigs {
			builder.AddData(os)
		}
		builder.AddData(input.RedeemScript)
		sigScript, err = builder.Script()
		if err != nil {
			return err
		}
	}

	if len(sigScript) > 0 {
		p.Inputs[inIndex].FinalScriptSig = sigScript
	}

	return nil
}

// finalizeTaprootInput attempts to finalize a taproot input
// key-path taproot: the witness is just the key signature
// script-path taproot: the witness is signatures of the first tapLeafScript, assuming it's a checksig tapscript
// all other cases must be finalized with custom finalizer function
func finalizeTaprootInput(p *Pset, inIndex int) error {
	if checkFinalScriptSigWitness(p, inIndex) {
		return ErrFinalizerAlreadyFinalized
	}

	input := p.Inputs[inIndex]

	// keypath finalization
	if len(input.TapKeySig) > 0 {
		witness := make([][]byte, 1)
		witness[0] = input.TapKeySig
		serializer := bufferutil.NewSerializer(nil)
		if err := serializer.WriteVector(witness); err != nil {
			return err
		}
		p.Inputs[inIndex].FinalScriptWitness = serializer.Bytes()
		return nil
	}

	// if scriptpath, we'll finalize the first tapScriptLeaf by default
	if len(input.TapScriptSig) > 0 {
		if len(input.TapLeafScript) == 0 {
			return ErrFinalizerForbiddenFinalization
		}

		leafToFinalize := input.TapLeafScript[0]
		leafToFinalizeHash := leafToFinalize.TapHash()
		signatures := make([][]byte, 0)
		for _, sig := range input.TapScriptSig {
			if bytes.Equal(sig.LeafHash, leafToFinalizeHash[:]) {
				signatures = append(signatures, sig.Signature)
			}
		}

		controlBlock, err := leafToFinalize.ControlBlock.ToBytes()
		if err != nil {
			return err
		}

		// witness = [signatures, script, controlBlock]
		witness := make([][]byte, 0, len(signatures)+2)
		witness = append(witness, signatures...)
		witness = append(witness, leafToFinalize.Script)
		witness = append(witness, controlBlock)

		serializer := bufferutil.NewSerializer(nil)
		if err := serializer.WriteVector(witness); err != nil {
			return err
		}

		p.Inputs[inIndex].FinalScriptWitness = serializer.Bytes()
		return nil
	}

	return ErrFinalizerForbiddenFinalization
}

// finalizeWitnessInput attempts to create PsetInFinalScriptSig field and
// PsetInFinalScriptWitness field for input at index inIndex, and removes all
// other fields except for the utxo field, for an input of type witness, or
// returns an error.
func finalizeWitnessInput(p *Pset, inIndex int) error {
	// If this input has already been finalized, then we'll return an error
	// as we can't proceed.
	if checkFinalScriptSigWitness(p, inIndex) {
		return ErrFinalizerAlreadyFinalized
	}

	// Depending on the actual output type, we'll either populate a
	// serializedWitness or a witness as well asa sigScript.
	var (
		sigScript         []byte
		serializedWitness []byte
	)

	input := p.Inputs[inIndex]

	// First we'll validate and collect the pubkey+sig pairs from the set
	// of partial signatures.
	var (
		pubKeys [][]byte
		sigs    [][]byte
	)
	for _, ps := range input.PartialSigs {
		pubKeys = append(pubKeys, ps.PubKey)

		sigOK := checkSigHashFlags(ps.Signature, input)
		if !sigOK {
			return ErrFinalizerInvalidSigHashFlags

		}

		sigs = append(sigs, ps.Signature)
	}

	// If at this point, we don't have any pubkey+sig pairs, then we bail
	// as we can't proceed.
	if len(sigs) == 0 || len(pubKeys) == 0 {
		return ErrFinalizerForbiddenFinalization
	}

	containsRedeemScript := len(input.RedeemScript) > 0
	containsWitnessScript := len(input.WitnessScript) > 0

	// If there's no redeem script, then we assume that this is native
	// segwit input.
	var err error
	if !containsRedeemScript {
		// If we have only a sigley pubkey+sig pair, and no witness
		// script, then we assume this is a P2WKH input.
		if len(pubKeys) == 1 && len(sigs) == 1 &&
			!containsWitnessScript {

			serializedWitness, err = writePKHWitness(
				sigs[0], pubKeys[0],
			)
			if err != nil {
				return err
			}
		} else {
			// Otherwise, we must have a witnessScript field, so
			// we'll generate a valid multi-sig witness.
			//
			// NOTE: We tacitly assume multisig.
			//
			// TODO(roasbeef): need to add custom finalize for
			// non-multisig P2WSH outputs (HTLCs, delay outputs,
			// etc).
			if !containsWitnessScript {
				return ErrFinalizerForbiddenFinalization
			}

			serializedWitness, err = getMultisigScriptWitness(
				input.WitnessScript, pubKeys, sigs,
			)
			if err != nil {
				return err
			}
		}
	} else {
		// Otherwise, we assume that this is a p2wsh multi-sig output,
		// which is nested in a p2sh, or a p2wkh nested in a p2sh.
		//
		// In this case, we'll take the redeem script (the witness
		// program in this case), and push it on the stack within the
		// sigScript.
		builder := txscript.NewScriptBuilder()
		builder.AddData(input.RedeemScript)
		sigScript, err = builder.Script()
		if err != nil {
			return err
		}

		// If don't have a witness script, then we assume this is a
		// nested p2wkh output.
		if !containsWitnessScript {
			// Assumed p2sh-p2wkh Here the witness is just (sig,
			// pub) as for p2pkh case
			if len(sigs) != 1 || len(pubKeys) != 1 {
				return ErrFinalizerForbiddenFinalization
			}

			serializedWitness, err = writePKHWitness(sigs[0], pubKeys[0])
			if err != nil {
				return err
			}

		} else {
			// Otherwise, we assume that this is a p2wsh multi-sig,
			// so we generate the proper witness.
			serializedWitness, err = getMultisigScriptWitness(
				input.WitnessScript, pubKeys, sigs,
			)
			if err != nil {
				return err
			}
		}
	}

	if len(sigScript) > 0 {
		p.Inputs[inIndex].FinalScriptSig = sigScript
	}

	if len(serializedWitness) > 0 {
		p.Inputs[inIndex].FinalScriptWitness = serializedWitness
	}
	return nil
}
