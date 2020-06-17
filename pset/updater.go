// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pset

// The Updater requires provision of a single PSBT and is able to add data to
// both input and output sections.  It can be called repeatedly to add more
// data.  It also allows addition of signatures via the addPartialSignature
// function; this is called internally to the package in the Sign() function of
// Updater, located in signer.go

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	NonConfidentialReissuanceTokenFlag = 0
	ConfidentialReissuanceTokenFlag    = 1
)

// Updater encapsulates the role 'Updater' as specified in BIP174; it accepts
// Psbt structs and has methods to add fields to the inputs and outputs.
type Updater struct {
	Upsbt *Pset
}

// NewUpdater returns a new instance of Updater, if the passed Psbt struct is
// in a valid form, else an error.
func NewUpdater(p *Pset) (*Updater, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, err
	}

	return &Updater{Upsbt: p}, nil

}

// AddInNonWitnessUtxo adds the utxo information for an input which is
// non-witness. This requires provision of a full transaction (which is the
// source of the corresponding prevOut), and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (p *Updater) AddInNonWitnessUtxo(tx *transaction.Transaction, inIndex int) error {
	if inIndex > len(p.Upsbt.Inputs)-1 {
		return psbt.ErrInvalidPrevOutNonWitnessTransaction
	}

	p.Upsbt.Inputs[inIndex].NonWitnessUtxo = tx

	if err := p.Upsbt.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// AddInWitnessUtxo adds the utxo information for an input which is witness.
// This requires provision of a full transaction *output* (which is the source
// of the corresponding prevOut); not the full transaction because BIP143 means
// the output information is sufficient, and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (p *Updater) AddInWitnessUtxo(txout *transaction.TxOutput, inIndex int) error {
	if inIndex > len(p.Upsbt.Inputs)-1 {
		return psbt.ErrInvalidPsbtFormat
	}

	p.Upsbt.Inputs[inIndex].WitnessUtxo = txout

	if err := p.Upsbt.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// addPartialSignature allows the Updater role to insert fields of type partial
// signature into a Pset, consisting of both the pubkey (as keydata) and the
// ECDSA signature (as value).  Note that the Signer role is encapsulated in
// this function; signatures are only allowed to be added that follow the
// sanity-check on signing rules explained in the BIP under `Signer`; if the
// rules are not satisfied, an ErrInvalidSignatureForInput is returned.
//
// NOTE: This function does *not* validate the ECDSA signature itself.
func (p *Updater) addPartialSignature(inIndex int, sig []byte,
	pubkey []byte) error {

	partialSig := psbt.PartialSig{
		PubKey: pubkey, Signature: sig,
	}

	// First validate the passed (sig, pub).
	if !checkValid(partialSig) {
		return psbt.ErrInvalidPsbtFormat
	}

	pInput := p.Upsbt.Inputs[inIndex]

	// First check; don't add duplicates.
	for _, x := range pInput.PartialSigs {
		if bytes.Equal(x.PubKey, partialSig.PubKey) {
			return psbt.ErrDuplicateKey
		}
	}

	// Next, we perform a series of additional sanity checks.
	if pInput.NonWitnessUtxo != nil {
		if len(p.Upsbt.UnsignedTx.Inputs) < inIndex+1 {
			return psbt.ErrInvalidPrevOutNonWitnessTransaction
		}

		if txHash := pInput.NonWitnessUtxo.TxHash(); !bytes.Equal(txHash[:], p.Upsbt.UnsignedTx.Inputs[inIndex].Hash) {
			return psbt.ErrInvalidSignatureForInput
		}

		// To validate that the redeem script matches, we must pull out
		// the scriptPubKey of the corresponding output and compare
		// that with the P2SH scriptPubKey that is generated by
		// redeemScript.
		if pInput.RedeemScript != nil {
			outIndex := p.Upsbt.UnsignedTx.Inputs[inIndex].Index
			scriptPubKey := pInput.NonWitnessUtxo.Outputs[outIndex].Script
			scriptHash := btcutil.Hash160(pInput.RedeemScript)

			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return psbt.ErrInvalidSignatureForInput
			}
		}

	} else if pInput.WitnessUtxo != nil {
		scriptPubKey := pInput.WitnessUtxo.Script

		var script []byte
		if pInput.RedeemScript != nil {
			scriptHash := btcutil.Hash160(pInput.RedeemScript)
			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return psbt.ErrInvalidSignatureForInput
			}

			script = pInput.RedeemScript
		} else {
			script = scriptPubKey
		}

		// If a witnessScript field is present, this is a P2WSH,
		// whether nested or not (that is handled by the assignment to
		// `script` above); in that case, sanity check that `script` is
		// the p2wsh of witnessScript. Contrariwise, if no
		// witnessScript field is present, this will be signed as
		// p2wkh.
		if pInput.WitnessScript != nil {
			witnessScriptHash := sha256.Sum256(pInput.WitnessScript)
			witnessScriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(witnessScriptHash[:]).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(script, witnessScriptHashScript[:]) {
				return psbt.ErrInvalidSignatureForInput
			}
		} else {
			// Otherwise, this is a p2wkh input.
			pubkeyHash := btcutil.Hash160(pubkey)
			pubkeyHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(pubkeyHash).
				Script()
			if err != nil {
				return err
			}

			// Validate that we're able to properly reconstruct the
			// witness program.
			if !bytes.Equal(pubkeyHashScript, script) {
				return psbt.ErrInvalidSignatureForInput
			}
		}
	} else {

		// Attaching signature without utxo field is not allowed.
		return psbt.ErrInvalidPsbtFormat
	}

	p.Upsbt.Inputs[inIndex].PartialSigs = append(
		p.Upsbt.Inputs[inIndex].PartialSigs, &partialSig,
	)

	if err := p.Upsbt.SanityCheck(); err != nil {
		return err
	}

	// Addition of a non-duplicate-key partial signature cannot violate
	// sanity-check rules.
	return nil
}

// AddInSighashType adds the sighash type information for an input.  The
// sighash type is passed as a 32 bit unsigned integer, along with the index
// for the input. An error is returned if addition of this key-value pair to
// the Psbt fails.
func (p *Updater) AddInSighashType(sighashType txscript.SigHashType,
	inIndex int) error {

	p.Upsbt.Inputs[inIndex].SighashType = sighashType

	if err := p.Upsbt.SanityCheck(); err != nil {
		return err
	}
	return nil
}

// AddInRedeemScript adds the redeem script information for an input.  The
// redeem script is passed serialized, as a byte slice, along with the index of
// the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (p *Updater) AddInRedeemScript(redeemScript []byte,
	inIndex int) error {

	p.Upsbt.Inputs[inIndex].RedeemScript = redeemScript

	if err := p.Upsbt.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// AddInWitnessScript adds the witness script information for an input.  The
// witness script is passed serialized, as a byte slice, along with the index
// of the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (p *Updater) AddInWitnessScript(witnessScript []byte,
	inIndex int) error {

	p.Upsbt.Inputs[inIndex].WitnessScript = witnessScript

	if err := p.Upsbt.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// AddInBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the input, and inserts this data into
// that input.
//
// NOTE: This can be called multiple times for the same input.  An error is
// returned if addition of this key-value pair to the Psbt fails.
func (p *Updater) AddInBip32Derivation(masterKeyFingerprint uint32,
	bip32Path []uint32, pubKeyData []byte, inIndex int) error {

	bip32Derivation := psbt.Bip32Derivation{
		PubKey:               pubKeyData,
		MasterKeyFingerprint: masterKeyFingerprint,
		Bip32Path:            bip32Path,
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return psbt.ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range p.Upsbt.Inputs[inIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return psbt.ErrDuplicateKey
		}
	}

	p.Upsbt.Inputs[inIndex].Bip32Derivation = append(
		p.Upsbt.Inputs[inIndex].Bip32Derivation, &bip32Derivation,
	)

	if err := p.Upsbt.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// AddOutBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the output, and inserts this data
// into that output.
//
// NOTE: That this can be called multiple times for the same output.  An error
// is returned if addition of this key-value pair to the Psbt fails.
func (p *Updater) AddOutBip32Derivation(masterKeyFingerprint uint32,
	bip32Path []uint32, pubKeyData []byte, outIndex int) error {

	bip32Derivation := psbt.Bip32Derivation{
		PubKey:               pubKeyData,
		MasterKeyFingerprint: masterKeyFingerprint,
		Bip32Path:            bip32Path,
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return psbt.ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range p.Upsbt.Outputs[outIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return psbt.ErrDuplicateKey
		}
	}

	p.Upsbt.Outputs[outIndex].Bip32Derivation = append(
		p.Upsbt.Outputs[outIndex].Bip32Derivation, &bip32Derivation,
	)

	if err := p.Upsbt.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// AddOutRedeemScript takes a redeem script as a byte slice and appends it to
// the output at index outIndex.
func (p *Updater) AddOutRedeemScript(redeemScript []byte,
	outIndex int) error {

	p.Upsbt.Outputs[outIndex].RedeemScript = redeemScript

	if err := p.Upsbt.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// AddOutWitnessScript takes a witness script as a byte slice and appends it to
// the output at index outIndex.
func (p *Updater) AddOutWitnessScript(witnessScript []byte,
	outIndex int) error {

	p.Upsbt.Outputs[outIndex].WitnessScript = witnessScript

	if err := p.Upsbt.SanityCheck(); err != nil {
		return err
	}

	return nil
}

//AddInput adds input to underlying unsignedTx
func (p *Updater) AddInput(txInput *transaction.TxInput) {
	p.Upsbt.UnsignedTx.AddInput(txInput)
	p.Upsbt.Inputs = append(p.Upsbt.Inputs, PInput{})
}

//AddOutput adds output to underlying unsignedTx
func (p *Updater) AddOutput(txOutput *transaction.TxOutput) {
	p.Upsbt.UnsignedTx.AddOutput(txOutput)
	p.Upsbt.Outputs = append(p.Upsbt.Outputs, POutput{})
}

type AddIssuanceArg struct {
	Precision    uint
	Contract     *transaction.IssuanceContract
	AssetAmount  float64
	TokenAmount  float64
	AssetAddress string
	TokenAddress string
	TokenFlag    uint
	Net          network.Network
}

//AddIssuance adds non-confidential issuance to the transaction
func (p *Updater) AddIssuance(arg AddIssuanceArg) error {
	if len(p.Upsbt.UnsignedTx.Inputs) == 0 {
		return errors.New("transaction must contain at least one input")
	}

	if arg.AssetAmount == 0 {
		return errors.New("asset amount must be greater then 0")
	}

	if arg.AssetAddress == "" {
		return errors.New("destination address for issued asset must" +
			" be provided")
	}

	if arg.TokenAmount > 0 {
		if arg.TokenAmount > 0 && arg.TokenAddress == "" {
			return errors.New("destination address for reissuance token " +
				"must be provided")
		}

		if arg.TokenFlag != NonConfidentialReissuanceTokenFlag &&
			arg.TokenFlag != ConfidentialReissuanceTokenFlag {
			return errors.New("token flag must be 0 or 1")
		}
	}

	issuance, err := transaction.NewTxIssuance(
		arg.AssetAmount,
		arg.TokenAmount,
		arg.Precision,
		arg.Contract,
	)
	if err != nil {
		return err
	}

	var prevoutIndex uint32
	var inputIndex int
	var prevoutHash [32]byte
	for i, input := range p.Upsbt.UnsignedTx.Inputs {
		if input.Issuance == nil {
			prevoutIndex = input.Index
			inputIndex = i
			copy(prevoutHash[:], input.Hash)
			break
		}
	}

	err = issuance.GenerateEntropy(prevoutHash[:], prevoutIndex)
	if err != nil {
		return err
	}

	p.Upsbt.UnsignedTx.Inputs[inputIndex].Issuance = &transaction.TxIssuance{
		AssetEntropy:       issuance.ContractHash,
		AssetAmount:        issuance.TxIssuance.AssetAmount,
		TokenAmount:        issuance.TxIssuance.TokenAmount,
		AssetBlindingNonce: issuance.TxIssuance.AssetBlindingNonce,
	}

	assetHash, err := issuance.GenerateAsset()
	if err != nil {
		return err
	}
	// prepend with a 0x01 prefix
	assetHash = append([]byte{0x01}, assetHash...)

	script, err := address.ToOutputScript(arg.AssetAddress, arg.Net)
	if err != nil {
		return err
	}

	output := transaction.NewTxOutput(
		assetHash,
		issuance.TxIssuance.AssetAmount,
		script,
	)
	p.AddOutput(output)

	if arg.TokenAmount > 0 {
		tokenHash, err := issuance.GenerateReissuanceToken(arg.TokenFlag)
		if err != nil {
			return err
		}
		tokenHash = append([]byte{byte(1)}, tokenHash...)
		script, err := address.ToOutputScript(arg.TokenAddress, arg.Net)
		if err != nil {
			return err
		}

		output := transaction.NewTxOutput(
			tokenHash,
			issuance.TxIssuance.TokenAmount,
			script,
		)
		p.AddOutput(output)
	}

	return nil
}
