// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pset

// signer encapsulates the role 'Signer' as specified in BIP174; it controls
// the insertion of signatures; the Sign() function will attempt to insert
// signatures using Updater.addPartialSignature, after first ensuring the Psbt
// is in the correct state.

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil/psbt"
)

// Sign allows the caller to sign a PSBT at a particular input; they
// must provide a signature and a pubkey, both as byte slices; they can also
// optionally provide both witnessScript and/or redeemScript, otherwise these
// arguments must be set as nil (and in that case, they must already be present
// in the PSBT if required for signing to succeed).
//
// This serves as a wrapper around Updater.addPartialSignature; it ensures that
// the redeemScript and witnessScript are updated as needed (note that the
// Updater is allowed to add redeemScripts and witnessScripts independently,
// before signing), and ensures that the right form of utxo field
// (NonWitnessUtxo or WitnessUtxo) is included in the input so that signature
// insertion (and then finalization) can take place.
func (p *Updater) Sign(inIndex int, sig []byte, pubKey []byte,
	redeemScript []byte, witnessScript []byte) (psbt.SignOutcome, error) {

	if isFinalized(p.Data, inIndex) {
		return psbt.SignFinalized, nil
	}

	// Add the witnessScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if witnessScript != nil {
		err := p.AddInWitnessScript(witnessScript, inIndex)
		if err != nil {
			return psbt.SignInvalid, err
		}
	}

	// Add the redeemScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if redeemScript != nil {
		err := p.AddInRedeemScript(redeemScript, inIndex)
		if err != nil {
			return psbt.SignInvalid, err
		}
	}

	// At this point, the PSBT must have the requisite witnessScript or
	// redeemScript fields for signing to succeed.
	//
	// Case 1: if witnessScript is present, it must be of type witness;
	// if not, signature insertion will of course fail.
	switch {
	case p.Data.Inputs[inIndex].WitnessScript != nil:
		if p.Data.Inputs[inIndex].WitnessUtxo == nil {
			err := nonWitnessToWitness(p.Data, inIndex)
			if err != nil {
				return psbt.SignInvalid, err
			}
		}

		err := p.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return psbt.SignInvalid, err
		}

	// Case 2: no witness script, only redeem script; can be legacy p2sh or
	// p2sh-wrapped p2wkh.
	case p.Data.Inputs[inIndex].RedeemScript != nil:
		// We only need to decide if the input is witness, and we don't
		// rely on the witnessutxo/nonwitnessutxo in the PSBT, instead
		// we check the redeemScript content.
		if txscript.IsWitnessProgram(redeemScript) {
			if p.Data.Inputs[inIndex].WitnessUtxo == nil {
				err := nonWitnessToWitness(p.Data, inIndex)
				if err != nil {
					return psbt.SignInvalid, err
				}
			}
		}

		// If it is not a valid witness program, we here assume that
		// the provided WitnessUtxo/NonWitnessUtxo field was correct.
		err := p.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return psbt.SignInvalid, err
		}

	// Case 3: Neither provided only works for native p2wkh, or non-segwit
	// non-p2sh. To check if it's segwit, check the scriptPubKey of the
	// output.
	default:
		if p.Data.Inputs[inIndex].WitnessUtxo == nil {
			outIndex := p.Data.UnsignedTx.Inputs[inIndex].Index
			script := p.Data.Inputs[inIndex].NonWitnessUtxo.Outputs[outIndex].Script

			if txscript.IsWitnessProgram(script) {
				err := nonWitnessToWitness(p.Data, inIndex)
				if err != nil {
					return psbt.SignInvalid, err
				}
			}
		}

		err := p.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return psbt.SignInvalid, err
		}
	}

	return psbt.SignSuccesful, nil
}

// nonWitnessToWitness extracts the TxOut from the existing NonWitnessUtxo
// field in the given PSBT input and sets it as type witness by replacing the
// NonWitnessUtxo field with a WitnessUtxo field. See
// https://github.com/bitcoin/bitcoin/pull/14197.
func nonWitnessToWitness(p *Pset, inIndex int) error {
	outIndex := p.UnsignedTx.Inputs[inIndex].Index
	txout := p.Inputs[inIndex].NonWitnessUtxo.Outputs[outIndex]

	// Remove the non-witness first, else sanity check will not pass:
	p.Inputs[inIndex].NonWitnessUtxo = nil
	u := Updater{
		Data: p,
	}

	return u.AddInWitnessUtxo(txout, inIndex)
}
