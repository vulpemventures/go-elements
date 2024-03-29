// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psetv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	NonConfidentialReissuanceTokenFlag = uint(0)
	ConfidentialReissuanceTokenFlag    = uint(1)
)

var (
	ErrInputIndexOutOfRange              = fmt.Errorf("provided input index is out of range")
	ErrOutputIndexOutOfRange             = fmt.Errorf("provided output index is out of range")
	ErrInvalidSignatureForInput          = fmt.Errorf("signature does not correspond to this input")
	ErrInIssuanceMissingAssetAddress     = fmt.Errorf("missing destination address for asset to (re)issue")
	ErrInIssuanceMissingTokenAddress     = fmt.Errorf("missing destination address for token to (re)issue")
	ErrInIssuanceAddressesMismatch       = fmt.Errorf("asset and token destination addresses must both be confidential or non-confidential")
	ErrPsetMissingInputForIssuance       = fmt.Errorf("pset must contain at least one input to add issuance to")
	ErrPsetMissingEmptyInputsForIssuance = fmt.Errorf("transaction does not contain any input with empty issuance")
	ErrInReissuanceMissingPrevout        = fmt.Errorf("either WitnessUtxo or NonWitnessUtxo must be defined")
	ErrInReissuanceInvalidTokenBlinder   = fmt.Errorf("invalid token prevout blinder length")
	ErrInReissuanceZeroTokenBlinder      = fmt.Errorf("token prevout blinder must not be a zero blinder")
	ErrInReissuanceInvalidAssetAmount    = fmt.Errorf("invalid reissuance asset amount")
	ErrInReissuanceInvalidTokenAmount    = fmt.Errorf("invalid reissuance token amount")
)

// Updater encapsulates the role 'Updater' as specified in BIP174; it accepts
// Psbt structs and has methods to add fields to the inputs and outputs.
type Updater struct {
	Pset *Pset
}

// NewUpdater returns a new instance of Updater, if the passed Psbt struct is
// in a valid form, else an error.a
func NewUpdater(p *Pset) (*Updater, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid pset: %s", err)
	}

	return &Updater{Pset: p}, nil
}

// AddInputs adds the provided inputs to the Pset
func (u *Updater) AddInputs(inputs []InputArgs) error {
	for i, in := range inputs {
		if err := in.validate(); err != nil {
			return fmt.Errorf("invalid input %d: %s", i, err)
		}
	}

	p := u.Pset.Copy()

	for _, in := range inputs {
		if err := p.addInput(in.toPartialInput()); err != nil {
			return fmt.Errorf("faile to add input: %s", err)
		}
	}

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddOutput adds the provided outputs to the Pset
func (u *Updater) AddOutputs(outputs []OutputArgs) error {
	for i, out := range outputs {
		if err := out.validate(); err != nil {
			return fmt.Errorf("invalid output args %d: %s", i, err)
		}
	}

	p := u.Pset.Copy()

	for _, out := range outputs {
		if err := p.addOutput(out.toPartialOutput()); err != nil {
			return fmt.Errorf("failed to add output: %s", err)
		}
	}

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddInNonWitnessUtxo adds the utxo information for an input which is
// non-witness. This requires provision of a full transaction (which is the
// source of the corresponding prevOut), and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (u *Updater) AddInNonWitnessUtxo(inIndex int, tx *transaction.Transaction) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	txid := tx.TxHash()
	if !bytes.Equal(txid[:], u.Pset.Inputs[inIndex].PreviousTxid) {
		return ErrInInvalidNonWitnessUtxo
	}
	u.Pset.Inputs[inIndex].NonWitnessUtxo = tx

	return u.Pset.SanityCheck()
}

// AddInWitnessUtxo adds the utxo information for an input which is witness.
// This requires provision of a full transaction *output* (which is the source
// of the corresponding prevOut); not the full transaction because BIP143 means
// the output information is sufficient, and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (u *Updater) AddInWitnessUtxo(inIndex int, txout *transaction.TxOutput) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	u.Pset.Inputs[inIndex].WitnessUtxo = txout

	return u.Pset.SanityCheck()
}

// AddInRedeemScript adds the redeem script information for an input.  The
// redeem script is passed serialized, as a byte slice, along with the index of
// the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (u *Updater) AddInRedeemScript(inIndex int, redeemScript []byte) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	u.Pset.Inputs[inIndex].RedeemScript = redeemScript

	return u.Pset.SanityCheck()
}

// AddInWitnessScript adds the witness script information for an input.  The
// witness script is passed serialized, as a byte slice, along with the index
// of the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (u *Updater) AddInWitnessScript(inIndex int, witnessScript []byte) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	u.Pset.Inputs[inIndex].WitnessScript = witnessScript

	return u.Pset.SanityCheck()
}

// AddInBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the input, and inserts this data into
// that input.
//
// NOTE: This can be called multiple times for the same input.  An error is
// returned if addition of this key-value pair to the Psbt fails.
func (u *Updater) AddInBip32Derivation(
	inIndex int, bip32Derivation DerivationPathWithPubKey,
) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range u.Pset.Inputs[inIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return ErrInDuplicatedField("bip32 derivation")
		}
	}

	u.Pset.Inputs[inIndex].Bip32Derivation = append(
		u.Pset.Inputs[inIndex].Bip32Derivation, bip32Derivation,
	)

	return u.Pset.SanityCheck()
}

// AddInSighashType adds the sighash type information for an input.  The
// sighash type is passed as a 32 bit unsigned integer, along with the index
// for the input. .
func (u *Updater) AddInSighashType(
	inIndex int, sighashType txscript.SigHashType,
) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	u.Pset.Inputs[inIndex].SigHashType = sighashType
	return u.Pset.SanityCheck()
}

// AddInUtxoRangeProof adds the prevout rangeproof for an input.
func (u *Updater) AddInUtxoRangeProof(
	inIndex int, proof []byte,
) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	u.Pset.Inputs[inIndex].UtxoRangeProof = proof
	return u.Pset.SanityCheck()
}

// AddInExplicitAsset adds the unconfidential asset hash and related blinding
// proof to the given confidential input.
// The proof should be calculate with confidential.CreateBlindAssetProof API.
func (u *Updater) AddInExplicitAsset(inIndex int, asset, proof []byte) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	if len(asset) != 32 {
		return fmt.Errorf("explicit asset must be exactly 32 bytes")
	}
	if len(proof) == 0 {
		return fmt.Errorf("missing asset blind proof")
	}

	prevout := u.Pset.Inputs[inIndex].GetUtxo()
	if prevout == nil {
		return fmt.Errorf("missing input prevout")
	}
	if !prevout.IsConfidential() {
		return fmt.Errorf(
			"explicit asset must be set only for confidential inputs",
		)
	}

	u.Pset.Inputs[inIndex].ExplicitAsset = asset
	u.Pset.Inputs[inIndex].AssetProof = proof
	return u.Pset.SanityCheck()
}

// AddInExplicitValue adds the unconfidential value and related blinding proof
// to the given confidential input.
// The proof should be calculate with confidential.CreateBlindValueProof API.
func (u *Updater) AddInExplicitValue(inIndex int, value uint64, proof []byte) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}
	if int(value) <= 0 {
		return fmt.Errorf("explicit value must be greater than 0")
	}
	if len(proof) == 0 {
		return fmt.Errorf("missing value blind proof")
	}

	prevout := u.Pset.Inputs[inIndex].GetUtxo()
	if prevout == nil {
		return fmt.Errorf("missing input prevout")
	}
	if !prevout.IsConfidential() {
		return fmt.Errorf(
			"explicit asset must be set only for confidential inputs",
		)
	}

	u.Pset.Inputs[inIndex].ExplicitValue = value
	u.Pset.Inputs[inIndex].ValueProof = proof
	return u.Pset.SanityCheck()
}

// AddInIssuanceArgs is a struct encapsulating all the issuance data that
// can be attached to any specific transaction of the PSBT.
type AddInIssuanceArgs struct {
	Precision       uint
	Contract        *transaction.IssuanceContract
	AssetAmount     uint64
	TokenAmount     uint64
	AssetAddress    string
	TokenAddress    string
	BlindedIssuance bool
}

func (arg AddInIssuanceArgs) validate() error {
	if _, err := transaction.NewTxIssuance(
		arg.AssetAmount, arg.TokenAmount, arg.Precision, arg.Contract,
	); err != nil {
		return err
	}

	if len(arg.AssetAddress) <= 0 {
		return ErrInIssuanceMissingAssetAddress
	}

	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return fmt.Errorf("invalid issuance asset address: %s", err)
	}

	if arg.TokenAmount > 0 {
		if len(arg.TokenAddress) <= 0 {
			return ErrInIssuanceMissingTokenAddress
		}
		if _, err := address.DecodeType(arg.TokenAddress); err != nil {
			return fmt.Errorf("invalid issuance token address: %s", err)
		}
	}

	return nil
}

func (arg AddInIssuanceArgs) tokenFlag() uint {
	if arg.BlindedIssuance {
		return uint(ConfidentialReissuanceTokenFlag)
	}
	return uint(NonConfidentialReissuanceTokenFlag)
}

func parseAddress(addr string) ([]byte, []byte) {
	script, _ := address.ToOutputScript(addr)
	isConf, _ := address.IsConfidential(addr)
	if !isConf {
		return script, nil
	}
	info, _ := address.FromConfidential(addr)
	return info.Script, info.BlindingKey
}

func (arg AddInIssuanceArgs) parseAssetAddress() ([]byte, []byte) {
	return parseAddress(arg.AssetAddress)
}

func (arg AddInIssuanceArgs) parseTokenAddress() ([]byte, []byte) {
	return parseAddress(arg.TokenAddress)
}

func (u *Updater) validateInputIndexForIssuance(inputIndex int) error {
	if inputIndex < 0 || inputIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	input := u.Pset.Inputs[inputIndex]
	if input.IssuanceAssetEntropy != nil {
		return fmt.Errorf("input %d already has an issuance", inputIndex)
	}

	return nil
}

// AddInIssuance adds an unblinded issuance to the transaction
func (u *Updater) AddInIssuance(inputIndex int, arg AddInIssuanceArgs) error {
	if err := arg.validate(); err != nil {
		return err
	}

	if len(u.Pset.Inputs) == 0 {
		return ErrPsetMissingInputForIssuance
	}

	if err := u.validateInputIndexForIssuance(inputIndex); err != nil {
		return err
	}

	p := u.Pset.Copy()
	input := p.Inputs[inputIndex]

	issuance, _ := transaction.NewTxIssuance(
		arg.AssetAmount,
		arg.TokenAmount,
		arg.Precision,
		arg.Contract,
	)

	if err := issuance.GenerateEntropy(input.PreviousTxid, input.PreviousTxIndex); err != nil {
		return err
	}

	p.Inputs[inputIndex].IssuanceAssetEntropy = issuance.ContractHash
	p.Inputs[inputIndex].IssuanceValue = arg.AssetAmount
	p.Inputs[inputIndex].IssuanceInflationKeys = arg.TokenAmount
	p.Inputs[inputIndex].IssuanceBlindingNonce = issuance.TxIssuance.AssetBlindingNonce
	p.Inputs[inputIndex].BlindedIssuance = &arg.BlindedIssuance

	rawAsset, _ := issuance.GenerateAsset()
	// prepend with a 0x01 prefix
	rawAsset = append([]byte{0x01}, rawAsset...)
	script, blindingKey := arg.parseAssetAddress()
	issuanceAsset := elementsutil.AssetHashFromBytes(rawAsset)
	issuanceOut := OutputArgs{
		Asset:        issuanceAsset,
		Amount:       arg.AssetAmount,
		Script:       script,
		BlindingKey:  blindingKey,
		BlinderIndex: uint32(inputIndex),
	}

	out := issuanceOut.toPartialOutput()
	if out.NeedsBlinding() {
		inIndex := uint32(inputIndex)
		out.BlinderIndex = inIndex
	}
	if err := p.addOutput(out); err != nil {
		return err
	}

	if arg.TokenAmount > 0 {
		rawAsset, _ := issuance.GenerateReissuanceToken(arg.tokenFlag())
		rawAsset = append([]byte{byte(1)}, rawAsset...)
		tokenAsset := elementsutil.AssetHashFromBytes(rawAsset)
		script, blindingKey := arg.parseTokenAddress()
		tokenOut := OutputArgs{
			Asset:        tokenAsset,
			Amount:       arg.TokenAmount,
			Script:       script,
			BlindingKey:  blindingKey,
			BlinderIndex: uint32(inputIndex),
		}
		out := tokenOut.toPartialOutput()
		if out.NeedsBlinding() {
			inIndex := uint32(inputIndex)
			out.BlinderIndex = inIndex
		}
		if err := p.addOutput(out); err != nil {
			return err
		}
	}

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddInReissuanceArgs defines the mandatory fields that one needs to pass to
// the AddInReissuance method of the *Updater type
//
//	PrevOutHash: the prevout hash of the token that will be added as input to the tx
//	PrevOutIndex: the prevout index of the token that will be added as input to the tx
//	PrevOutBlinder: the asset blinder used to blind the prevout token
//	WitnessUtxo: the prevout token in case it is a witness one
//	NonWitnessUtxo: the prevout tx that include the token output in case it is a non-witness one
//	Entropy: the entropy used to generate token and asset
//	AssetAmount: the amount of asset to re-issue
//	TokenAmount: the same unblinded amount of the prevout token
//	AssetAddress: the destination address of the re-issuing asset
//	TokenAddress: the destination address of the re-issuance token
type AddInReissuanceArgs struct {
	TokenPrevOutBlinder []byte
	Entropy             string
	AssetAmount         uint64
	AssetAddress        string
	TokenAmount         uint64
	TokenAddress        string
}

func (arg AddInReissuanceArgs) validate() error {
	if len(arg.TokenPrevOutBlinder) != 32 {
		return ErrInReissuanceInvalidTokenBlinder
	}
	if bytes.Equal(arg.TokenPrevOutBlinder, zeroBlinder) {
		return ErrInReissuanceZeroTokenBlinder
	}

	if buf, err := hex.DecodeString(arg.Entropy); err != nil || len(buf) != 32 {
		return ErrInInvalidIssuanceAssetEntropy
	}

	if arg.AssetAmount == 0 {
		return ErrInReissuanceInvalidAssetAmount
	}

	if arg.TokenAmount == 0 {
		return ErrInReissuanceInvalidTokenAmount
	}

	if len(arg.AssetAddress) <= 0 {
		return ErrInIssuanceMissingAssetAddress
	}
	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return fmt.Errorf("invalid reissuance asset address: %s", err)
	}
	if len(arg.TokenAddress) <= 0 {
		return ErrInIssuanceMissingTokenAddress
	}
	if _, err := address.DecodeType(arg.TokenAddress); err != nil {
		return fmt.Errorf("invalid reissuance token address: %s", err)
	}

	return nil
}

func (arg AddInReissuanceArgs) parseAssetAddress() ([]byte, []byte) {
	return parseAddress(arg.AssetAddress)
}

func (arg AddInReissuanceArgs) parseTokenAddress() ([]byte, []byte) {
	return parseAddress(arg.TokenAddress)
}

// AddInReissuance takes care of adding an input (the prevout token) and 2
// outputs to the partial transaction. It also creates a new (re)issuance with
// the provided entropy, blinder and amounts and attaches it to the new input.
// NOTE: This transaction must be blinded later so that a new token blinding
// nonce is generated for the new token output
func (u *Updater) AddInReissuance(inputIndex int, arg AddInReissuanceArgs) error {
	if err := u.validateInputIndexForIssuance(inputIndex); err != nil {
		return err
	}

	if err := arg.validate(); err != nil {
		return err
	}

	p := u.Pset.Copy()

	entropy, _ := hex.DecodeString(arg.Entropy)
	entropy = elementsutil.ReverseBytes(entropy)
	issuance := transaction.NewTxIssuanceFromEntropy(entropy)

	rawAsset, _ := issuance.GenerateAsset()
	rawAsset = append([]byte{0x01}, rawAsset...)
	reissuedAsset := elementsutil.AssetHashFromBytes(rawAsset)

	script, blindingKey := arg.parseAssetAddress()

	reissuanceOut := OutputArgs{
		Asset:       reissuedAsset,
		Amount:      arg.AssetAmount,
		Script:      script,
		BlindingKey: blindingKey,
	}

	out := reissuanceOut.toPartialOutput()
	if out.NeedsBlinding() {
		out.BlinderIndex = uint32(inputIndex)
	}
	if err := p.addOutput(out); err != nil {
		return err
	}

	rawAsset, _ = issuance.GenerateReissuanceToken(
		ConfidentialReissuanceTokenFlag,
	)
	rawAsset = append([]byte{0x01}, rawAsset...)
	tokenAsset := elementsutil.AssetHashFromBytes(rawAsset)

	tokenScript, tokenBlindingKey := arg.parseTokenAddress()

	tokenOut := OutputArgs{
		Asset:       tokenAsset,
		Amount:      arg.TokenAmount,
		Script:      tokenScript,
		BlindingKey: tokenBlindingKey,
	}

	out = tokenOut.toPartialOutput()
	if out.NeedsBlinding() {
		out.BlinderIndex = uint32(inputIndex)
	}
	if err := p.addOutput(out); err != nil {
		return err
	}

	// add the (re)issuance to the token input. The token amount of the issuance
	// must not be defined for reissunces.
	p.Inputs[inputIndex].IssuanceAssetEntropy = entropy
	p.Inputs[inputIndex].IssuanceValue = arg.AssetAmount
	p.Inputs[inputIndex].IssuanceBlindingNonce = arg.TokenPrevOutBlinder

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddInTapInternalKey adds a taproot internal key to the input at index inIndex.
// it returns an error if the input has already a TapInternalKey.
func (u *Updater) AddInTapInternalKey(inIndex int, internalKey []byte) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	if len(u.Pset.Inputs[inIndex].TapInternalKey) > 0 {
		return ErrInDuplicatedField("tap internal key")
	}

	u.Pset.Inputs[inIndex].TapInternalKey = internalKey
	return u.Pset.SanityCheck()
}

// AddInTapMerkleRoot adds the taproot tree root to the input at index inIndex.
// it returns an error if the input has already a TapMerkleRoot.
func (u *Updater) AddInTapMerkleRoot(inIndex int, tapMerkleRoot []byte) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	if len(u.Pset.Inputs[inIndex].TapMerkleRoot) > 0 {
		return ErrInDuplicatedField("tap merkle root")
	}

	u.Pset.Inputs[inIndex].TapMerkleRoot = tapMerkleRoot
	return u.Pset.SanityCheck()
}

// AddInTapLeafScript adds TapLeafScript to the input at index inIndex.
// It returns an error if the input has already a TapLeafScript with the same TapHash.
func (u *Updater) AddInTapLeafScript(inIndex int, tapLeafScript TapLeafScript) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	p := u.Pset.Copy()
	if p.Inputs[inIndex].TapLeafScript == nil {
		p.Inputs[inIndex].TapLeafScript = make([]TapLeafScript, 0)
	}
	h := tapLeafScript.TapHash()
	for _, tls := range p.Inputs[inIndex].TapLeafScript {
		currentHash := tls.TapHash()

		if bytes.Equal(currentHash[:], h[:]) {
			return ErrInDuplicatedField("tap leaf script")
		}
	}

	p.Inputs[inIndex].TapLeafScript = append(p.Inputs[inIndex].TapLeafScript, tapLeafScript)

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddInTapBip32Derivation adds TapBip32Derivation to the input at index inIndex.
func (u *Updater) AddInTapBip32Derivation(inIndex int, tapBip32Derivation TapDerivationPathWithPubKey) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	p := u.Pset.Copy()
	if p.Inputs[inIndex].TapBip32Derivation == nil {
		p.Inputs[inIndex].TapBip32Derivation = make([]TapDerivationPathWithPubKey, 0)
	}

	p.Inputs[inIndex].TapBip32Derivation = append(p.Inputs[inIndex].TapBip32Derivation, tapBip32Derivation)

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddOutBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the output, and inserts this data
// into that output.
//
// NOTE: That this can be called multiple times for the same output.  An error
// is returned if addition of this key-value pair to the Psbt fails.
func (u *Updater) AddOutBip32Derivation(
	outIndex int, bip32Derivation DerivationPathWithPubKey,
) error {
	if outIndex > int(u.Pset.Global.OutputCount)-1 {
		return ErrOutputIndexOutOfRange
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range u.Pset.Outputs[outIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return ErrOutDuplicatedField("bip32 derivation")
		}
	}

	u.Pset.Outputs[outIndex].Bip32Derivation = append(
		u.Pset.Outputs[outIndex].Bip32Derivation, bip32Derivation,
	)

	return u.Pset.SanityCheck()
}

// AddOutRedeemScript takes a redeem script as a byte slice and appends it to
// the output at index outIndex.
func (u *Updater) AddOutRedeemScript(outIndex int, redeemScript []byte) error {
	if outIndex > int(u.Pset.Global.OutputCount)-1 {
		return ErrOutputIndexOutOfRange
	}

	u.Pset.Outputs[outIndex].RedeemScript = redeemScript
	return u.Pset.SanityCheck()
}

// AddOutWitnessScript takes a witness script as a byte slice and appends it to
// the output at index outIndex.
func (u *Updater) AddOutWitnessScript(outIndex int, witnessScript []byte) error {
	if outIndex > int(u.Pset.Global.OutputCount)-1 {
		return ErrOutputIndexOutOfRange
	}

	u.Pset.Outputs[outIndex].WitnessScript = witnessScript
	return u.Pset.SanityCheck()
}

// addPartialSignature allows the Updater role to insert fields of type partial
// signature into a Pset, consisting of both the pubkey (as keydata) and the
// ECDSA signature (as value).  Note that the Signer role is encapsulated in
// this function; signatures are only allowed to be added that follow the
// sanity-check on signing rules explained in the BIP under `Signer`; if the
// rules are not satisfied, an ErrInvalidSignatureForInput is returned.
//
// NOTE: This function does *not* validate the ECDSA signature itself.
func (u *Updater) addPartialSignature(inIndex int, sig, pubkey []byte) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	partialSig := PartialSig{
		PubKey: pubkey, Signature: sig,
	}

	// First validate the passed (sig, pub).
	if !partialSig.checkValid() {
		return ErrInvalidPsbtFormat
	}

	input := u.Pset.Inputs[inIndex]

	// First check; don't add duplicates.
	for _, x := range input.PartialSigs {
		if bytes.Equal(x.PubKey, partialSig.PubKey) {
			return ErrInDuplicatedField("partial sig")
		}
	}

	// Next, we perform a series of additional sanity checks.
	if input.NonWitnessUtxo != nil {
		if txHash := input.NonWitnessUtxo.TxHash(); !bytes.Equal(txHash[:], input.PreviousTxid) {
			return ErrInvalidSignatureForInput
		}

		// To validate that the redeem script matches, we must pull out
		// the scriptPubKey of the corresponding output and compare
		// that with the P2SH scriptPubKey that is generated by
		// redeemScript.
		if input.RedeemScript != nil {
			outIndex := input.PreviousTxIndex
			scriptPubKey := input.NonWitnessUtxo.Outputs[outIndex].Script
			scriptHash := btcutil.Hash160(input.RedeemScript)

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
	} else if input.WitnessUtxo != nil {
		scriptPubKey := input.WitnessUtxo.Script

		var script []byte
		if input.RedeemScript != nil {
			scriptHash := btcutil.Hash160(input.RedeemScript)
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

			script = input.RedeemScript
		} else {
			script = scriptPubKey
		}

		// If a witnessScript field is present, this is a P2WSH,
		// whether nested or not (that is handled by the assignment to
		// `script` above); in that case, sanity check that `script` is
		// the p2wsh of witnessScript. Contrariwise, if no
		// witnessScript field is present, this will be signed as
		// p2wkh.
		if input.WitnessScript != nil {
			witnessScriptHash := sha256.Sum256(input.WitnessScript)
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

	u.Pset.Inputs[inIndex].PartialSigs = append(
		u.Pset.Inputs[inIndex].PartialSigs, partialSig,
	)

	return u.Pset.SanityCheck()
}

// nonWitnessToWitness extracts the TxOut from the existing NonWitnessUtxo
// field in the given PSBT input and sets it as type witness by replacing the
// NonWitnessUtxo field with a WitnessUtxo field. See
// https://github.com/bitcoin/bitcoin/pull/14197.
func (u *Updater) nonWitnessToWitness(inIndex int) error {
	if inIndex > int(u.Pset.Global.InputCount)-1 {
		return ErrInputIndexOutOfRange
	}

	outIndex := u.Pset.Inputs[inIndex].PreviousTxIndex
	txout := u.Pset.Inputs[inIndex].NonWitnessUtxo.Outputs[outIndex]

	// Remove the non-witness first, else sanity check will not pass:
	u.Pset.Inputs[inIndex].NonWitnessUtxo = nil

	return u.AddInWitnessUtxo(inIndex, txout)
}
