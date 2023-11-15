// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psetv2

// signer encapsulates the role 'Signer' as specified in BIP174; it controls
// the insertion of signatures; the Sign() function will attempt to insert
// signatures using UpdaterRole.addPartialSignature, after first ensuring the Psbt
// is in the correct state.

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
)

var (
	ErrSignerForbiddenSigning                       = fmt.Errorf("pset is not fully blinded")
	ErrSignerForbiddenTaprootKeySigHasTapscriptSigs = fmt.Errorf("pset input has tapscript signatures")
	ErrSignerForbiddenTaprootScriptSigHasKeySig     = fmt.Errorf("pset input has taproot key signature")
)

type Signer = Updater

func NewSigner(pset *Pset) (*Signer, error) {
	if err := pset.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid pset: %s", err)
	}
	return &Signer{pset}, nil
}

// SignInput allows the caller to sign a PSET at a particular input; they
// must provide a signature and a pubkey, both as byte slices; they can also
// optionally provide both witnessScript and/or redeemScript, otherwise these
// arguments must be set as nil (and in that case, they must already be present
// in the PSBT if required for signing to succeed).
//
// This serves as a wrapper around UpdaterRole.addPartialSignature; it ensures that
// the redeemScript and witnessScript are updated as needed (note that the
// UpdaterRole is allowed to add redeemScripts and witnessScripts independently,
// before signing), and ensures that the right form of utxo field
// (NonWitnessUtxo or WitnessUtxo) is included in the input so that signature
// insertion (and then finalization) can take place.
func (s *Signer) SignInput(
	inIndex int, sig, pubKey, redeemScript, witnessScript []byte,
) error {
	if inIndex < 0 || inIndex >= int(s.Pset.Global.InputCount) {
		return ErrInputIndexOutOfRange
	}

	p := s.Pset.Copy()
	input := s.Pset.Inputs[inIndex]

	if isFinalized(p, inIndex) {
		return nil
	}

	if (input.SigHashType & 0x1f) == txscript.SigHashAll {
		for _, out := range p.Outputs {
			if out.NeedsBlinding() && !out.IsFullyBlinded() {
				return ErrSignerForbiddenSigning
			}
		}
	}

	// Add the witnessScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if witnessScript != nil {
		if err := s.AddInWitnessScript(inIndex, witnessScript); err != nil {
			return fmt.Errorf("failed to add input witness script: %s", err)
		}
	}

	// Add the redeemScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if redeemScript != nil {
		if err := s.AddInRedeemScript(inIndex, redeemScript); err != nil {
			return fmt.Errorf("failed to add input redeem script: %s", err)
		}
	}

	// At this point, the PSBT must have the requisite witnessScript or
	// redeemScript fields for signing to succeed.
	//
	// Case 1: if witnessScript is present, it must be of type witness;
	// if not, signature insertion will of course fail.
	switch {
	case p.Inputs[inIndex].WitnessScript != nil:
		if p.Inputs[inIndex].WitnessUtxo == nil {
			if err := s.nonWitnessToWitness(inIndex); err != nil {
				return fmt.Errorf(
					"failed to parse non-witness to witness utxo: %s", err,
				)
			}
		}

	// Case 2: no witness script, only redeem script; can be legacy p2sh or
	// p2sh-wrapped p2wkh.
	case p.Inputs[inIndex].RedeemScript != nil:
		// We only need to decide if the input is witness, and we don't
		// rely on the witnessutxo/nonwitnessutxo in the PSBT, instead
		// we check the redeemScript content.
		if txscript.IsWitnessProgram(redeemScript) {
			if p.Inputs[inIndex].WitnessUtxo == nil {
				if err := s.nonWitnessToWitness(inIndex); err != nil {
					return fmt.Errorf(
						"failed to parse non-witness to witness utxo: %s", err,
					)
				}
			}
		}

	// Case 3: Neither provided only works for native p2wkh, or non-segwit
	// non-p2sh. To check if it's segwit, check the scriptPubKey of the
	// output.
	default:
		if p.Inputs[inIndex].WitnessUtxo == nil {
			outIndex := s.Pset.Inputs[inIndex].PreviousTxIndex
			script := s.Pset.Inputs[inIndex].NonWitnessUtxo.Outputs[outIndex].Script

			if txscript.IsWitnessProgram(script) {
				if err := s.nonWitnessToWitness(inIndex); err != nil {
					return fmt.Errorf(
						"failed to parse non-witness to witness utxo: %s", err,
					)
				}
			}
		}
	}

	if err := s.addPartialSignature(inIndex, sig, pubKey); err != nil {
		return fmt.Errorf("failed to add signature for input %d: %s", inIndex, err)
	}

	s.Pset.Global = p.Global
	s.Pset.Inputs = p.Inputs
	s.Pset.Outputs = p.Outputs
	return s.Pset.SanityCheck()
}

// SignTaprootInputKeySig adds a taproot key-path signature to the input at inIndex
// it returns an error if the input has tapscript signatures or if the input is already signed with key signature
func (s *Signer) SignTaprootInputKeySig(
	inIndex int, sig []byte,
) error {
	if inIndex < 0 || inIndex >= int(s.Pset.Global.InputCount) {
		return ErrInputIndexOutOfRange
	}

	p := s.Pset.Copy()

	if isFinalized(p, inIndex) {
		return nil
	}

	if p.Inputs[inIndex].TapScriptSig != nil {
		return ErrInDuplicatedField("tapscript sig")
	}

	if p.Inputs[inIndex].TapScriptSig != nil && len(p.Inputs[inIndex].TapScriptSig) > 0 {
		return ErrSignerForbiddenTaprootKeySigHasTapscriptSigs
	}

	p.Inputs[inIndex].TapKeySig = sig

	s.Pset.Global = p.Global
	s.Pset.Inputs = p.Inputs
	s.Pset.Outputs = p.Outputs
	return s.Pset.SanityCheck()
}

// SignTaprootInputTapscriptSig adds a taproot tapscript signature to the input at inIndex
// it returns an error if the input is signed with key-path signature
func (s *Signer) SignTaprootInputTapscriptSig(
	inIndex int, tapscriptSig TapScriptSig,
) error {
	if inIndex < 0 || inIndex >= int(s.Pset.Global.InputCount) {
		return ErrInputIndexOutOfRange
	}

	p := s.Pset.Copy()

	if isFinalized(p, inIndex) {
		return nil
	}

	if p.Inputs[inIndex].TapKeySig != nil {
		return ErrSignerForbiddenTaprootScriptSigHasKeySig
	}

	if p.Inputs[inIndex].TapScriptSig == nil {
		p.Inputs[inIndex].TapScriptSig = make([]TapScriptSig, 0)
	}

	p.Inputs[inIndex].TapScriptSig = append(p.Inputs[inIndex].TapScriptSig, tapscriptSig)

	s.Pset.Global = p.Global
	s.Pset.Inputs = p.Inputs
	s.Pset.Outputs = p.Outputs
	return s.Pset.SanityCheck()
}
