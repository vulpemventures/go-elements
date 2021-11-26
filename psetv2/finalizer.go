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
	"errors"

	"github.com/btcsuite/btcd/txscript"
)

var (
	// ErrInvalidSigHashFlags indicates that a signature added to the PSBT
	// uses Sighash flags that are not in accordance with the requirement
	// according to the entry in PsbtInSighashType, or otherwise not the
	// default value (SIGHASH_ALL)
	ErrInvalidSigHashFlags = errors.New("invalid sighash flags")
	// ErrNotFinalizable indicates that the PSBT struct does not have
	// sufficient data (e.g. signatures) for finalization
	ErrNotFinalizable = errors.New("PSBT is not finalizable")
	// ErrInputAlreadyFinalized indicates that the PSBT passed to a Finalizer
	// already contains the finalized scriptSig or witness.
	ErrInputAlreadyFinalized = errors.New("cannot finalize PSBT, finalized " +
		"scriptSig or scriptWitnes already exists")
)

type Finalizer struct {
	pset *Pset
}

func NewFinalizer(pset *Pset) *Finalizer {

	return &Finalizer{
		pset: pset,
	}
}

// FinalizeAll finalizes all inputs of a partial elements transaction by
// calling the Finalize function for every partial input
func (f *Finalizer) FinalizeAll(p *Pset) error {
	for inIndex := range p.Inputs {
		err := f.Finalize(p, inIndex)
		if err != nil {
			return err
		}
	}
	return nil
}

// Finalize assumes that the provided pset.Pset struct has all partial
// signatures and redeem scripts/witness scripts already prepared for the
// specified input, and so removes all temporary data and replaces them with
// completed sigScript and witness fields, which are stored in key-types 07 and
// 08. The witness/non-witness utxo fields in the inputs (key-types 00 and 01)
// are left intact as they may be needed for validation (?).  If there is any
// invalid or incomplete data, an error is returned.
func (f *Finalizer) Finalize(p *Pset, inIndex int) error {
	input := p.Inputs[inIndex]

	// Depending on the UTXO type, we either attempt to finalize it as a
	// witness or legacy UTXO.
	switch {
	case input.witnessUtxo != nil:
		if err := finalizeWitnessInput(p, inIndex); err != nil {
			return err
		}

	case input.nonWitnessUtxo != nil:
		if err := finalizeNonWitnessInput(p, inIndex); err != nil {
			return err
		}

	default:
		return ErrInvalidPsbtFormat
	}

	// Before returning we sanity check the PSET to ensure we don't extract
	// an invalid transaction or produce an invalid intermediate state.
	if err := p.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// MaybeFinalizeAll attempts to finalize all inputs of the pset.Pset that are
// not already finalized, and returns an error if it fails to do so.
func (f *Finalizer) MaybeFinalizeAll(p *Pset) error {

	for i := range p.Inputs {
		success, err := f.MaybeFinalize(p, i)
		if err != nil || !success {
			return err
		}
	}

	return nil
}

// MaybeFinalize attempts to finalize the input at index inIndex in the PSET p,
// returning true with no error if it succeeds, OR if the input has already
// been finalized.
func (f *Finalizer) MaybeFinalize(p *Pset, inIndex int) (bool, error) {
	if isFinalized(p, inIndex) {
		return true, nil
	}

	if !isFinalizable(p, inIndex) {
		return false, ErrNotFinalizable
	}

	if err := f.Finalize(p, inIndex); err != nil {
		return false, err
	}

	return true, nil
}

// isFinalized considers this input finalized if it contains at least one of
// the FinalScriptSig or FinalScriptWitness are filled (which only occurs in a
// successful call to Finalize*).
func isFinalized(p *Pset, inIndex int) bool {
	input := p.Inputs[inIndex]
	return input.finalScriptSig != nil || input.finalScriptWitness != nil
}

// isFinalizableWitnessInput returns true if the target input is a witness UTXO
// that can be finalized.
func isFinalizableWitnessInput(input *Input) bool {
	pkScript := input.witnessUtxo.Script

	switch {
	// If this is a native witness output, then we require both
	// the witness script, but not a redeem script.
	case txscript.IsWitnessProgram(pkScript):
		if txscript.IsPayToWitnessScriptHash(pkScript) {
			if input.witnessScript == nil ||
				input.redeemScript != nil {
				return false
			}
		} else {
			// A P2WKH output on the other hand doesn't need
			// neither a witnessScript or redeemScript.
			if input.witnessScript != nil ||
				input.redeemScript != nil {
				return false
			}
		}

	// For nested P2SH inputs, we verify that a witness script is known.
	case txscript.IsPayToScriptHash(pkScript):
		if input.redeemScript == nil {
			return false
		}

		// If this is a nested P2SH input, then it must also have a
		// witness script, while we don't need one for P2WKH.
		if txscript.IsPayToWitnessScriptHash(input.redeemScript) {
			if input.witnessScript == nil {
				return false
			}
		} else if txscript.IsPayToWitnessPubKeyHash(input.redeemScript) {
			if input.witnessScript != nil {
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
	if input.witnessScript != nil {
		return false
	}

	// Otherwise, we'll verify that we only have a RedeemScript if the prev
	// output script is P2SH.
	outIndex := p.Inputs[inIndex].previousOutputIndex
	if txscript.IsPayToScriptHash(input.nonWitnessUtxo.Outputs[*outIndex].Script) {
		if input.redeemScript == nil {
			return false
		}
	} else {
		if input.redeemScript != nil {
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
	if input.partialSigs == nil {
		return false
	}

	// For an input to be finalized, we'll one of two possible top-level
	// UTXOs present. Each UTXO type has a distinct set of requirements to
	// be considered finalized.
	switch {

	// A witness input must be either native P2WSH or nested P2SH with all
	// relevant sigScript or witness data populated.
	case input.witnessUtxo != nil:
		if !isFinalizableWitnessInput(&input) {
			return false
		}

	case input.nonWitnessUtxo != nil:
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

	if input.finalScriptSig != nil {
		return true
	}

	if input.finalScriptWitness != nil {
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
		return ErrInputAlreadyFinalized
	}

	// Our goal here is to construct a sigScript given the pubkey,
	// signature (keytype 02), of which there might be multiple, and the
	// redeem script field (keytype 04) if present (note, it is not present
	// for p2pkh type inputs).
	var sigScript []byte

	input := p.Inputs[inIndex]
	containsRedeemScript := input.redeemScript != nil

	var (
		pubKeys [][]byte
		sigs    [][]byte
	)
	for _, ps := range input.partialSigs {
		pubKeys = append(pubKeys, ps.PubKey)

		sigOK := checkSigHashFlags(ps.Signature, input)
		if !sigOK {
			return ErrInvalidSigHashFlags
		}

		sigs = append(sigs, ps.Signature)
	}

	// We have failed to identify at least 1 (sig, pub) pair in the PSET,
	// which indicates it was not ready to be finalized. As a result, we
	// can't proceed.
	if len(sigs) < 1 || len(pubKeys) < 1 {
		return ErrNotFinalizable
	}

	// If this input doesn't need a redeem script (P2PKH), then we'll
	// construct a simple sigScript that's just the signature then the
	// pubkey (OP_CHECKSIG).
	var err error
	if !containsRedeemScript {
		// At this point, we should only have a single signature and
		// pubkey.
		if len(sigs) != 1 || len(pubKeys) != 1 {
			return ErrNotFinalizable
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
			input.redeemScript, pubKeys, sigs,
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
		builder.AddData(input.redeemScript)
		sigScript, err = builder.Script()
		if err != nil {
			return err
		}
	}

	if len(sigScript) > 0 {
		p.Inputs[inIndex].finalScriptSig = sigScript
	}

	return nil
}

// finalizeWitnessInput attempts to create PsetInFinalScriptSig field and
// PsetInFinalScriptWitness field for input at index inIndex, and removes all
// other fields except for the utxo field, for an input of type witness, or
// returns an error.
func finalizeWitnessInput(p *Pset, inIndex int) error {
	// If this input has already been finalized, then we'll return an error
	// as we can't proceed.
	if checkFinalScriptSigWitness(p, inIndex) {
		return ErrInputAlreadyFinalized
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
	for _, ps := range input.partialSigs {
		pubKeys = append(pubKeys, ps.PubKey)

		sigOK := checkSigHashFlags(ps.Signature, input)
		if !sigOK {
			return ErrInvalidSigHashFlags

		}

		sigs = append(sigs, ps.Signature)
	}

	// If at this point, we don't have any pubkey+sig pairs, then we bail
	// as we can't proceed.
	if len(sigs) == 0 || len(pubKeys) == 0 {
		return ErrNotFinalizable
	}

	containsRedeemScript := input.redeemScript != nil
	containsWitnessScript := input.witnessScript != nil

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
				return ErrNotFinalizable
			}

			serializedWitness, err = getMultisigScriptWitness(
				input.witnessScript, pubKeys, sigs,
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
		builder.AddData(input.redeemScript)
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
				return ErrNotFinalizable
			}

			serializedWitness, err = writePKHWitness(sigs[0], pubKeys[0])
			if err != nil {
				return err
			}

		} else {
			// Otherwise, we assume that this is a p2wsh multi-sig,
			// so we generate the proper witness.
			serializedWitness, err = getMultisigScriptWitness(
				input.witnessScript, pubKeys, sigs,
			)
			if err != nil {
				return err
			}
		}
	}

	if len(sigScript) > 0 {
		p.Inputs[inIndex].finalScriptSig = sigScript
	}

	if len(serializedWitness) > 0 {
		p.Inputs[inIndex].finalScriptWitness = serializedWitness
	}
	return nil
}
