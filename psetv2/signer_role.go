// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psetv2

// signer encapsulates the role 'SignerRole' as specified in BIP174; it controls
// the insertion of signatures; the Sign() function will attempt to insert
// signatures using UpdaterRole.addPartialSignature, after first ensuring the Psbt
// is in the correct state.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/payment"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
)

const (
	// SignSuccesful indicates that the partial signature was successfully
	// attached.
	SignSuccesful = 0

	// SignFinalized  indicates that this input is already finalized, so the provided
	// signature was *not* attached
	SignFinalized = 1

	// SignInvalid indicates that the provided signature data was not valid. In this case
	// an error will also be returned.
	SignInvalid = -1

	// SignBlindingNotDone indicates that blinding is not done
	SignBlindingNotDone = 2

	// SignBlindingProofsInvalid indicates that blinding proofs are invalid
	SignBlindingProofsInvalid = 3
)

type SignerRole struct {
	pset       *Pset
	blinderSvc Blinder
	updater    *UpdaterRole
}

func NewSignerRole(pset *Pset, blinderSvc Blinder) (*SignerRole, error) {
	updater, err := NewUpdaterRole(pset)
	if err != nil {
		return nil, err
	}

	return &SignerRole{
		pset:       pset,
		blinderSvc: blinderSvc,
		updater:    updater,
	}, nil
}

// SignOutcome is a enum-like value that expresses the outcome of a call to the
// Sign method.
type SignOutcome int

// SignInput allows the caller to sign a PSBT at a particular input; they
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
func (s *SignerRole) SignInput(
	inIndex int,
	sig []byte,
	pubKey []byte,
	redeemScript []byte,
	witnessScript []byte,
) (SignOutcome, error) {
	if isFinalized(s.pset, inIndex) {
		return SignFinalized, nil
	}

	if !s.pset.blinded() {
		return SignBlindingNotDone, nil
	}

	proofsValid, err := s.blindProofsValid()
	if err != nil {
		return 0, err
	}
	if !proofsValid {
		return SignBlindingProofsInvalid, nil
	}

	// Add the witnessScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if witnessScript != nil {
		err := s.updater.AddInWitnessScript(witnessScript, inIndex)
		if err != nil {
			return SignInvalid, err
		}
	}

	// Add the redeemScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if redeemScript != nil {
		err := s.updater.AddInRedeemScript(redeemScript, inIndex)
		if err != nil {
			return SignInvalid, err
		}
	}

	// At this point, the PSBT must have the requisite witnessScript or
	// redeemScript fields for signing to succeed.
	//
	// Case 1: if witnessScript is present, it must be of type witness;
	// if not, signature insertion will of course fail.
	switch {
	case s.pset.Inputs[inIndex].witnessScript != nil:
		if s.pset.Inputs[inIndex].witnessUtxo == nil {
			err := nonWitnessToWitness(s.pset, inIndex)
			if err != nil {
				return SignInvalid, err
			}
		}

		err := s.updater.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}

	// Case 2: no witness script, only redeem script; can be legacy p2sh or
	// p2sh-wrapped p2wkh.
	case s.pset.Inputs[inIndex].redeemScript != nil:
		// We only need to decide if the input is witness, and we don't
		// rely on the witnessutxo/nonwitnessutxo in the PSBT, instead
		// we check the redeemScript content.
		if txscript.IsWitnessProgram(redeemScript) {
			if s.pset.Inputs[inIndex].witnessUtxo == nil {
				err := nonWitnessToWitness(s.pset, inIndex)
				if err != nil {
					return SignInvalid, err
				}
			}
		}

		// If it is not a valid witness program, we here assume that
		// the provided WitnessUtxo/NonWitnessUtxo field was correct.
		err := s.updater.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}

	// Case 3: Neither provided only works for native p2wkh, or non-segwit
	// non-p2sh. To check if it's segwit, check the scriptPubKey of the
	// output.
	default:
		if s.pset.Inputs[inIndex].witnessUtxo == nil {
			outIndex := s.pset.Inputs[inIndex].previousOutputIndex
			script := s.pset.Inputs[inIndex].nonWitnessUtxo.Outputs[*outIndex].Script

			if txscript.IsWitnessProgram(script) {
				err := nonWitnessToWitness(s.pset, inIndex)
				if err != nil {
					return SignInvalid, err
				}
			}
		}

		err := s.updater.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}
	}

	return SignSuccesful, nil
}

// nonWitnessToWitness extracts the TxOut from the existing NonWitnessUtxo
// field in the given PSBT input and sets it as type witness by replacing the
// NonWitnessUtxo field with a WitnessUtxo field. See
// https://github.com/bitcoin/bitcoin/pull/14197.
func nonWitnessToWitness(p *Pset, inIndex int) error {
	outIndex := p.Inputs[inIndex].previousOutputIndex
	txout := p.Inputs[inIndex].nonWitnessUtxo.Outputs[*outIndex]

	// Remove the non-witness first, else sanity check will not pass:
	p.Inputs[inIndex].nonWitnessUtxo = nil
	u := UpdaterRole{
		pset: p,
	}

	return u.AddInWitnessUtxo(txout, inIndex)
}

func (s *SignerRole) blindProofsValid() (bool, error) {
	for _, v := range s.pset.Outputs {
		if v.ToBlind() {
			if !v.IsBlinded() {
				return false, nil
			}

			if v.outputAmount != nil {
				valid, err := s.blinderSvc.VerifyBlindValueProof(
					*v.outputAmount,
					v.outputValueCommitment,
					v.outputBlindValueProof,
					v.outputAssetCommitment,
				)
				if err != nil {
					return false, err
				}

				if !valid {
					return false, nil
				}
			}

			if v.outputAsset != nil {
				valid, err := s.blinderSvc.VerifyBlindAssetProof(
					v.outputAsset[1:],
					v.outputBlindAssetProof,
					v.outputAssetCommitment,
				)
				if err != nil {
					return false, err
				}

				if !valid {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

func (s *SignerRole) ValidateAllSignatures() (bool, error) {
	for i := range s.pset.Inputs {
		valid, err := s.ValidateInputSignatures(i)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, nil
		}
	}
	return true, nil
}

func (s *SignerRole) ValidateInputSignatures(inputIndex int) (
	bool,
	error,
) {
	if len(s.pset.Inputs[inputIndex].partialSigs) > 0 {
		for _, v := range s.pset.Inputs[inputIndex].partialSigs {
			valid, err := s.validatePartialSignature(inputIndex, v)
			if err != nil {
				return false, err
			}
			if !valid {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

func (s *SignerRole) validatePartialSignature(
	inputIndex int,
	partialSignature PartialSig,
) (bool, error) {
	if partialSignature.PubKey == nil {
		return false, errors.New("no pub key for partial signature")
	}

	signatureLen := len(partialSignature.Signature)
	sigHashType := partialSignature.Signature[signatureLen-1]
	signatureDer := partialSignature.Signature[:signatureLen-1]

	sigHash, script, err := s.getHashAndScriptForSignature(
		inputIndex,
		uint32(sigHashType),
	)
	if err != nil {
		return false, err
	}

	valid, err := s.verifyScriptForPubKey(script, partialSignature.PubKey)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}

	pSig, err := btcec.ParseDERSignature(signatureDer, btcec.S256())
	if err != nil {
		return false, nil
	}

	pubKey, err := btcec.ParsePubKey(partialSignature.PubKey, btcec.S256())
	if err != nil {
		return false, nil
	}

	return pSig.Verify(sigHash[:], pubKey), nil
}

func (s *SignerRole) getHashAndScriptForSignature(inputIndex int, sigHashType uint32) (
	[]byte,
	[]byte,
	error,
) {
	var hash [32]byte
	var script []byte

	tx, err := s.pset.UnsignedTx(s.blinderSvc)
	if err != nil {
		return nil, nil, err
	}

	input := s.pset.Inputs[inputIndex]
	if input.nonWitnessUtxo != nil {
		prevoutHash := input.previousTxid
		utxoHash := input.nonWitnessUtxo.TxHash()

		if bytes.Compare(prevoutHash, utxoHash.CloneBytes()) == 1 {
			return nil, nil,
				errors.New("non-witness utxo hash for input doesnt match the " +
					"hash specified in the prevout")
		}

		prevoutIndex := input.previousOutputIndex
		prevout := input.nonWitnessUtxo.Outputs[*prevoutIndex]
		if input.redeemScript != nil {
			script = input.redeemScript
		} else {
			script = prevout.Script
		}

		switch address.GetScriptType(script) {

		case address.P2WshScript:
			if input.witnessScript == nil {
				return nil, nil,
					errors.New("segwit input needs witnessScript if not p2wpkh")
			}

			hash = tx.HashForWitnessV0(
				inputIndex,
				input.witnessScript,
				prevout.Value,
				txscript.SigHashType(sigHashType),
			)
			script = input.witnessScript

		case address.P2WpkhScript:
			pay, err := payment.FromScript(
				script,
				nil,
				nil,
			)
			if err != nil {
				return nil, nil, err
			}
			hash = tx.HashForWitnessV0(
				inputIndex,
				pay.Script,
				input.witnessUtxo.Value,
				txscript.SigHashType(sigHashType),
			)
		default:
			var err error
			hash, err = tx.HashForSignature(
				inputIndex,
				script,
				txscript.SigHashType(sigHashType),
			)
			if err != nil {
				return nil, nil, err
			}
		}
	} else if input.witnessUtxo != nil {
		if input.redeemScript != nil {
			script = input.redeemScript
		} else {
			script = input.witnessUtxo.Script
		}
		switch address.GetScriptType(script) {

		case address.P2WpkhScript:
			pay, err := payment.FromScript(
				script,
				nil,
				nil,
			)
			if err != nil {
				return nil, nil, err
			}
			hash = tx.HashForWitnessV0(
				inputIndex,
				pay.Script,
				input.witnessUtxo.Value,
				txscript.SigHashType(sigHashType),
			)
		case address.P2WshScript:
			hash = tx.HashForWitnessV0(
				inputIndex,
				input.witnessScript,
				input.witnessUtxo.Value,
				txscript.SigHashType(sigHashType),
			)
			script = input.witnessScript
		default:
			return nil, nil, errors.New("inputhas witnessUtxo but non-segwit script")
		}

	} else {
		return nil, nil, errors.New("need a utxo input item for signing")
	}

	return hash[:], script, nil
}

func (s *SignerRole) verifyScriptForPubKey(
	script []byte,
	pubKey []byte,
) (bool, error) {

	pk, err := btcec.ParsePubKey(pubKey, btcec.S256())
	if err != nil {
		return false, err
	}

	pkHash := payment.Hash160(pubKey)

	scriptAsm, err := txscript.DisasmString(script)
	if err != nil {
		return false, err
	}

	if strings.Contains(
		scriptAsm,
		hex.EncodeToString(pk.SerializeCompressed()),
	) || strings.Contains(
		scriptAsm,
		hex.EncodeToString(pkHash),
	) {
		return true, nil
	}

	return false, nil
}
