package psetv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"

	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

const (
	NonConfidentialReissuanceTokenFlag = 0
	ConfidentialReissuanceTokenFlag    = 1
)

var (
	ErrInvalidPrevOutNonWitnessTransaction = errors.New("prevout hash does " +
		"not match the provided non-witness utxo serialization")
	ErrDuplicateKey = errors.New("invalid psbt due to duplicate key")
)

// Updater encapsulates the role 'Updater' as specified in BIP174; it accepts
// Psbt structs and has methods to add fields to the inputs and outputs.
type Updater struct {
	pset *Pset
}

// NewUpdater returns a new instance of Updater, if the passed Psbt struct is
// in a valid form, else an error.a
func NewUpdater(p *Pset) (*Updater, error) {

	return &Updater{pset: p}, nil
}

// AddInNonWitnessUtxo adds the utxo information for an input which is
// non-witness. This requires provision of a full transaction (which is the
// source of the corresponding prevOut), and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (p *Updater) AddInNonWitnessUtxo(inIndex int, tx *transaction.Transaction) error {
	if inIndex > len(p.pset.Inputs)-1 {
		return ErrInvalidPrevOutNonWitnessTransaction
	}
	p.pset.Inputs[inIndex].nonWitnessUtxo = tx

	return nil
}

// AddInWitnessUtxo adds the utxo information for an input which is witness.
// This requires provision of a full transaction *output* (which is the source
// of the corresponding prevOut); not the full transaction because BIP143 means
// the output information is sufficient, and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (p *Updater) AddInWitnessUtxo(txout *transaction.TxOutput, inIndex int) error {
	if inIndex > len(p.pset.Inputs)-1 {
		return ErrInvalidPsbtFormat
	}
	p.pset.Inputs[inIndex].witnessUtxo = txout

	return nil
}

// AddInRedeemScript adds the redeem script information for an input.  The
// redeem script is passed serialized, as a byte slice, along with the index of
// the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (p *Updater) AddInRedeemScript(redeemScript []byte, inIndex int) error {
	p.pset.Inputs[inIndex].redeemScript = redeemScript

	return nil
}

// AddInWitnessScript adds the witness script information for an input.  The
// witness script is passed serialized, as a byte slice, along with the index
// of the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (p *Updater) AddInWitnessScript(witnessScript []byte, inIndex int) error {
	p.pset.Inputs[inIndex].witnessScript = witnessScript

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

	bip32Derivation := DerivationPathWithPubKey{
		PubKey:               pubKeyData,
		MasterKeyFingerprint: masterKeyFingerprint,
		Bip32Path:            bip32Path,
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range p.pset.Inputs[inIndex].bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return ErrDuplicateKey
		}
	}

	p.pset.Inputs[inIndex].bip32Derivation = append(
		p.pset.Inputs[inIndex].bip32Derivation, bip32Derivation,
	)

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

	bip32Derivation := DerivationPathWithPubKey{
		PubKey:               pubKeyData,
		MasterKeyFingerprint: masterKeyFingerprint,
		Bip32Path:            bip32Path,
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range p.pset.Outputs[outIndex].bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return ErrDuplicateKey
		}
	}

	p.pset.Outputs[outIndex].bip32Derivation = append(
		p.pset.Outputs[outIndex].bip32Derivation, bip32Derivation,
	)

	return nil
}

// AddOutRedeemScript takes a redeem script as a byte slice and appends it to
// the output at index outIndex.
func (p *Updater) AddOutRedeemScript(redeemScript []byte, outIndex int) error {
	p.pset.Outputs[outIndex].redeemScript = redeemScript

	return nil
}

// AddOutWitnessScript takes a witness script as a byte slice and appends it to
// the output at index outIndex.
func (p *Updater) AddOutWitnessScript(witnessScript []byte, outIndex int) error {
	p.pset.Outputs[outIndex].witnessScript = witnessScript

	return nil
}

// AddInput adds input to the pset
func (p *Updater) AddInput(inputArg InputArg) error {
	return p.pset.addInput(inputArg)
}

// AddOutput adds output to the pset
func (p *Updater) AddOutput(outputArg OutputArg) error {
	return p.pset.addOutput(outputArg)
}

// AddIssuanceArgs is a struct encapsulating all the issuance data that
// can be attached to any specific transaction of the PSBT.
type AddIssuanceArgs struct {
	Precision    uint
	Contract     *transaction.IssuanceContract
	AssetAmount  uint64
	TokenAmount  uint64
	AssetAddress string
	TokenAddress string
}

func (arg AddIssuanceArgs) validate() error {
	if _, err := transaction.NewTxIssuance(
		arg.AssetAmount,
		arg.TokenAmount,
		arg.Precision,
		arg.Contract,
	); err != nil {
		return err
	}

	if len(arg.AssetAddress) <= 0 {
		return errors.New("missing destination address for asset to issue")
	}

	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return err
	}

	if arg.TokenAmount > 0 {
		if len(arg.TokenAddress) <= 0 {
			return errors.New("missing destination address for token to issue")
		}
		if _, err := address.DecodeType(arg.TokenAddress); err != nil {
			return err
		}
	}
	if !arg.matchAddressTypes() {
		return errors.New(
			"asset and token destination addresses must both be confidential or " +
				"non-confidential",
		)
	}

	return nil
}

func (arg AddIssuanceArgs) matchAddressTypes() bool {
	if len(arg.TokenAddress) <= 0 {
		return true
	}

	a, _ := address.IsConfidential(arg.AssetAddress)
	b, _ := address.IsConfidential(arg.TokenAddress)
	// xnor -> return true only if a and b have the same value
	return !((a || b) && (!a || !b))
}

func (arg AddIssuanceArgs) tokenFlag() uint {
	if isConfidential, _ := address.IsConfidential(
		arg.AssetAddress,
	); isConfidential {
		return uint(ConfidentialReissuanceTokenFlag)
	}
	return uint(NonConfidentialReissuanceTokenFlag)
}

// AddIssuance adds an unblinded issuance to the transaction
func (p *Updater) AddIssuance(arg AddIssuanceArgs) error {
	if err := arg.validate(); err != nil {
		return err
	}

	if len(p.pset.Inputs) == 0 {
		return errors.New("transaction must contain at least one input")
	}

	issuance, _ := transaction.NewTxIssuance(
		arg.AssetAmount,
		arg.TokenAmount,
		arg.Precision,
		arg.Contract,
	)

	prevoutIndex, prevoutHash, inputIndex := findInputWithEmptyIssuance(p.pset)
	if inputIndex < 0 {
		return errors.New(
			"transaction does not contain any input with empty issuance",
		)
	}

	if err := issuance.GenerateEntropy(
		prevoutHash[:],
		prevoutIndex,
	); err != nil {
		return err
	}

	amount, err := elementsutil.ElementsToSatoshiValue(issuance.TxIssuance.AssetAmount)
	if err != nil {
		return err
	}
	issuanceValue := int64(amount)

	amount, err = elementsutil.ElementsToSatoshiValue(issuance.TxIssuance.TokenAmount)
	if err != nil {
		return err
	}
	tokenValue := int64(amount)

	p.pset.Inputs[inputIndex].issuanceAssetEntropy = issuance.ContractHash
	p.pset.Inputs[inputIndex].issuanceValue = &issuanceValue
	p.pset.Inputs[inputIndex].issuanceInflationKeys = &tokenValue
	p.pset.Inputs[inputIndex].issuanceBlindingNonce = issuance.TxIssuance.AssetBlindingNonce

	assetHash, err := issuance.GenerateAsset()
	if err != nil {
		return err
	}
	// prepend with a 0x01 prefix
	assetHash = append([]byte{0x01}, assetHash...)

	script, err := address.ToOutputScript(arg.AssetAddress)
	if err != nil {
		return err
	}

	output := transaction.NewTxOutput(
		assetHash,
		issuance.TxIssuance.AssetAmount,
		script,
	)
	if err := p.AddOutput(OutputArg{TxOutput: *output}); err != nil {
		return err
	}

	if arg.TokenAmount > 0 {
		tokenHash, err := issuance.GenerateReissuanceToken(arg.tokenFlag())
		if err != nil {
			return err
		}
		tokenHash = append([]byte{byte(1)}, tokenHash...)
		script, err := address.ToOutputScript(arg.TokenAddress)
		if err != nil {
			return err
		}

		output := transaction.NewTxOutput(
			tokenHash,
			issuance.TxIssuance.TokenAmount,
			script,
		)
		if err := p.AddOutput(OutputArg{TxOutput: *output}); err != nil {
			return err
		}
	}

	return nil
}

// AddReissuanceArgs defines the mandatory fields that one needs to pass to
// the AddReissuance method of the *Updater type
// 		PrevOutHash: the prevout hash of the token that will be added as input to the tx
//		PrevOutIndex: the prevout index of the token that will be added as input to the tx
//		PrevOutBlinder: the asset blinder used to blind the prevout token
//		WitnessUtxo: the prevout token in case it is a witness one
//		NonWitnessUtxo: the prevout tx that include the token output in case it is a non witness one
//		Entropy: the entropy used to generate token and asset
//		AssetAmount: the amount of asset to re-issue
//		TokenAmount: the same unblinded amount of the prevout token
//		AssetAddress: the destination address of the re-issuing asset
//		TokenAddress: the destination address of the re-issuance token
type AddReissuanceArgs struct {
	PrevOutHash    string
	PrevOutIndex   uint32
	PrevOutBlinder []byte
	WitnessUtxo    *transaction.TxOutput
	NonWitnessUtxo *transaction.Transaction
	Entropy        string
	AssetAmount    uint64
	AssetAddress   string
	TokenAmount    uint64
	TokenAddress   string
}

func (arg AddReissuanceArgs) validate() error {
	if arg.WitnessUtxo == nil && arg.NonWitnessUtxo == nil {
		return errors.New("either WitnessUtxo or NonWitnessUtxo must be defined")
	}

	if buf, err := hex.DecodeString(arg.PrevOutHash); err != nil || len(buf) != 32 {
		return errors.New("invalid input hash")
	}

	if arg.NonWitnessUtxo != nil {
		hash := arg.NonWitnessUtxo.TxHash()
		if hex.EncodeToString(elementsutil.ReverseBytes(hash[:])) != arg.PrevOutHash {
			return errors.New("input and non witness utxo hashes must match")
		}
	}

	// it's mandatory for the token prevout to be confidential. This because the
	// prevout value blinder will be used as the reissuance's blinding nonce to
	// prove that the spender actually owns and can unblind the token output.
	if !arg.isPrevoutConfidential() {
		return errors.New(
			"token prevout must be confidential. You must blind your token by " +
				"sending it to yourself in a confidential transaction if you want " +
				"be able to reissue the relative asset",
		)
	}

	if len(arg.PrevOutBlinder) != 32 {
		return errors.New("invalid input blinder")
	}

	if buf, err := hex.DecodeString(arg.Entropy); err != nil || len(buf) != 32 {
		return errors.New("invalid asset entropy")
	}

	if arg.AssetAmount <= 0 {
		return errors.New("invalid asset amount")
	}

	if arg.TokenAmount <= 0 {
		return errors.New("invalid token amount")
	}

	if len(arg.AssetAddress) <= 0 {
		return errors.New("invalid destination address for asset")
	}
	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return err
	}
	if len(arg.TokenAddress) <= 0 {
		return errors.New("invalid destination address for token")
	}
	if _, err := address.DecodeType(arg.TokenAddress); err != nil {
		return err
	}
	if !arg.areAddressesConfidential() {
		return errors.New("asset and token address must be both confidential")
	}

	return nil
}

func (arg AddReissuanceArgs) isPrevoutConfidential() bool {
	if arg.WitnessUtxo != nil {
		return arg.WitnessUtxo.IsConfidential()
	}
	return arg.NonWitnessUtxo.Outputs[arg.PrevOutIndex].IsConfidential()
}

func (arg AddReissuanceArgs) areAddressesConfidential() bool {
	a, _ := address.IsConfidential(arg.AssetAddress)
	b, _ := address.IsConfidential(arg.TokenAddress)
	return a && b
}

// AddReissuance takes care of adding an input (the prevout token) and 2
// outputs to the partial transaction. It also creates a new (re)issuance with
// the provided entropy, blinder and amounts and attaches it to the new input.
// NOTE: This transaction must be blinded later so that a new token blinding
// nonce is generated for the new token output
func (p *Updater) AddReissuance(arg AddReissuanceArgs) error {
	if err := arg.validate(); err != nil {
		return err
	}

	if len(p.pset.Inputs) == 0 {
		return errors.New(
			"transaction must contain at least one input before adding a reissuance",
		)
	}

	prevoutHash, _ := hex.DecodeString(arg.PrevOutHash)
	prevoutHash = elementsutil.ReverseBytes(prevoutHash)
	prevoutIndex := arg.PrevOutIndex

	// add input
	tokenInput := transaction.NewTxInput(prevoutHash, prevoutIndex)
	if err := p.AddInput(InputArg{TxInput: *tokenInput}); err != nil {
		return err
	}
	inputIndex := len(p.pset.Inputs) - 1
	if arg.WitnessUtxo != nil {
		if err := p.AddInWitnessUtxo(arg.WitnessUtxo, inputIndex); err != nil {
			return err
		}
	} else {
		if err := p.AddInNonWitnessUtxo(inputIndex, arg.NonWitnessUtxo); err != nil {
			return err
		}
	}

	entropy, _ := hex.DecodeString(arg.Entropy)
	entropy = elementsutil.ReverseBytes(entropy)
	issuance := transaction.NewTxIssuanceFromEntropy(entropy)

	assetHash, _ := issuance.GenerateAsset()
	assetHash = append([]byte{0x01}, assetHash...)
	assetScript, _ := address.ToOutputScript(arg.AssetAddress)
	assetAmount, _ := elementsutil.SatoshiToElementsValue(arg.AssetAmount)

	tokenHash, _ := issuance.GenerateReissuanceToken(
		ConfidentialReissuanceTokenFlag,
	)
	tokenHash = append([]byte{0x01}, tokenHash...)
	tokenScript, _ := address.ToOutputScript(arg.TokenAddress)
	tokenAmount, _ := elementsutil.SatoshiToElementsValue(arg.TokenAmount)

	// add outputs
	reissuanceOutput := transaction.NewTxOutput(
		assetHash,
		assetAmount,
		assetScript,
	)
	if err := p.AddOutput(OutputArg{TxOutput: *reissuanceOutput}); err != nil {
		return err
	}

	// and the token output
	tokenOutput := transaction.NewTxOutput(
		tokenHash,
		tokenAmount,
		tokenScript,
	)
	if err := p.AddOutput(OutputArg{TxOutput: *tokenOutput}); err != nil {
		return err
	}

	// add the (re)issuance to the token input. The token amount of the issuance
	// must not be defined for reissunces.
	issuanceValue := int64(arg.AssetAmount)
	var issuanceInflationKeys int64 = 0

	p.pset.Inputs[inputIndex].issuanceAssetEntropy = issuance.ContractHash
	p.pset.Inputs[inputIndex].issuanceValue = &issuanceValue
	p.pset.Inputs[inputIndex].issuanceInflationKeys = &issuanceInflationKeys
	p.pset.Inputs[inputIndex].issuanceBlindingNonce = arg.PrevOutBlinder

	return nil
}

func findInputWithEmptyIssuance(p *Pset) (uint32, []byte, int) {
	for i, in := range p.Inputs {
		if in.issuanceValue == nil {
			return *in.previousOutputIndex, in.previousTxid[:], i
		}
	}
	return 0, nil, -1
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

	partialSig := PartialSig{
		PubKey: pubkey, Signature: sig,
	}

	// First validate the passed (sig, pub).
	if !partialSig.checkValid() {
		return ErrInvalidPsbtFormat
	}

	input := p.pset.Inputs[inIndex]

	// First check; don't add duplicates.
	for _, x := range input.partialSigs {
		if bytes.Equal(x.PubKey, partialSig.PubKey) {
			return ErrDuplicateKey
		}
	}

	// Next, we perform a series of additional sanity checks.
	if input.nonWitnessUtxo != nil {
		if txHash := input.nonWitnessUtxo.TxHash(); !bytes.Equal(txHash[:], p.pset.Inputs[inIndex].previousTxid) {
			return ErrInvalidSignatureForInput
		}

		// To validate that the redeem script matches, we must pull out
		// the scriptPubKey of the corresponding output and compare
		// that with the P2SH scriptPubKey that is generated by
		// redeemScript.
		if input.redeemScript != nil {
			outIndex := p.pset.Inputs[inIndex].previousOutputIndex
			scriptPubKey := input.nonWitnessUtxo.Outputs[*outIndex].Script
			scriptHash := btcutil.Hash160(input.redeemScript)

			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return ErrInvalidSignatureForInput
			}
		}

	} else if input.witnessUtxo != nil {
		scriptPubKey := input.witnessUtxo.Script

		var script []byte
		if input.redeemScript != nil {
			scriptHash := btcutil.Hash160(input.redeemScript)
			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return ErrInvalidSignatureForInput
			}

			script = input.redeemScript
		} else {
			script = scriptPubKey
		}

		// If a witnessScript field is present, this is a P2WSH,
		// whether nested or not (that is handled by the assignment to
		// `script` above); in that case, sanity check that `script` is
		// the p2wsh of witnessScript. Contrariwise, if no
		// witnessScript field is present, this will be signed as
		// p2wkh.
		if input.witnessScript != nil {
			witnessScriptHash := sha256.Sum256(input.witnessScript)
			witnessScriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(witnessScriptHash[:]).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(script, witnessScriptHashScript[:]) {
				return ErrInvalidSignatureForInput
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
				return ErrInvalidSignatureForInput
			}
		}
	} else {

		// Attaching signature without utxo field is not allowed.
		return ErrInvalidPsbtFormat
	}

	p.pset.Inputs[inIndex].partialSigs = append(
		p.pset.Inputs[inIndex].partialSigs, partialSig,
	)

	if err := p.pset.SanityCheck(); err != nil {
		return err
	}

	// Addition of a non-duplicate-key partial signature cannot violate
	// sanity-check rules.
	return nil
}
