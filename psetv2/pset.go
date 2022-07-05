package psetv2

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/payment"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"

	"github.com/vulpemventures/go-elements/transaction"
)

const (
	separator         = 0x00
	maxPsbtKeyLength  = 10000
	minTimeLockTime   = 500000000
	maxHeightLockTime = 499999999

	PsetProprietary = 0xfc
)

var (
	magicPrefix              = []byte{0x70, 0x73, 0x65, 0x74}
	magicPrefixWithSeparator = append(magicPrefix, 0xff)

	ErrInvalidPsbtFormat        = fmt.Errorf("invalid PSBT serialization format")
	ErrNoMoreKeyPairs           = fmt.Errorf("no more key-pairs")
	ErrInvalidMagicBytes        = fmt.Errorf("invalid magic bytes")
	ErrDuplicateKey             = fmt.Errorf("invalid psbt due to duplicate key")
	ErrPsetMissingBlindedOutput = fmt.Errorf(
		"pset has blinded inputs, at least one output must be blinded",
	)
	ErrPsetInvalidGlobablModifiableState = fmt.Errorf(
		"global modifiable flag must be unset for fully blinded pset",
	)
	ErrPsetForbiddenInputsModification = fmt.Errorf(
		"pset locked for modifications on inputs",
	)
	ErrPsetForbiddenOutputsModification = fmt.Errorf(
		"pset locked for modifications on outputs",
	)
	ErrPartialSignatureMissingPubKey = fmt.Errorf(
		"input partial signature is missing pubkey",
	)
)

// Pset - Partially Signed Elements Transaction
//Format:
//<pset> := <magic> <global-map> <input-map>* <output-map>*
//<magic> := 0x70 0x73 0x65 0x74 0xFF -> pset starts with magic bytes, after which goes global map
//followed by more input-map's and output-map's
//<global-map> := <keypair>* 0x00 -> there is one global-map, there can be many keypair's, global map ends with separator
//<input-map> := <keypair>* 0x00 -> there can be many input-map's, there can be many keypair's, input map ends with separator
//<output-map> := <keypair>* 0x00 -> there can be many output-map's, there can be many keypair's, output map ends with separator
//<keypair> := <key> <value>
//<key> := <keylen> <keytype> <keydata>
//<value> := <valuelen> <valuedata>
// Each map can contain ProprietaryData data and unknowns keypair's
// Full spec: https://github.com/ElementsProject/elements/blob/master/doc/pset.mediawiki
type Pset struct {
	Global  Global
	Inputs  []Input
	Outputs []Output
}

func NewPsetFromBuffer(buf *bytes.Buffer) (*Pset, error) {
	return deserialize(buf)
}

func NewPsetFromBase64(psetBase64 string) (*Pset, error) {
	psetBytes, err := base64.StdEncoding.DecodeString(psetBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pset in base64 format: %s", err)
	}

	return deserialize(bytes.NewBuffer(psetBytes))
}

func (p *Pset) ToBase64() (string, error) {
	buf, err := p.serialize()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf), nil
}

func (p *Pset) Copy() *Pset {
	return &Pset{
		Global:  p.Global,
		Inputs:  p.Inputs,
		Outputs: p.Outputs,
	}
}

func (p *Pset) InputsModifiable() bool {
	if p.Global.TxModifiable != nil {
		return p.Global.TxModifiable.Test(0)
	}
	return true
}

func (p *Pset) OutputsModifiable() bool {
	if p.Global.TxModifiable != nil {
		return p.Global.TxModifiable.Test(1)
	}
	return true
}

func (p *Pset) HasSighashSingle() bool {
	if p.Global.TxModifiable == nil {
		return false
	}
	return p.Global.TxModifiable.Test(2)
}

func (p *Pset) NeedsBlinding() bool {
	if p.Global.Modifiable != nil {
		return p.Global.Modifiable.Test(0)
	}

	for _, out := range p.Outputs {
		if out.IsBlinded() && !out.IsFullyBlinded() {
			return true
		}
	}
	return false
}

func (p *Pset) IsFullyBlinded() bool {
	if !p.NeedsBlinding() {
		return false
	}
	if p.Global.Modifiable != nil {
		return !p.Global.Modifiable.Test(0)
	}
	for _, out := range p.Outputs {
		if out.IsBlinded() && !out.IsFullyBlinded() {
			return false
		}
	}
	return true
}

func (p *Pset) IsComplete() bool {
	for i := 0; i < len(p.Inputs); i++ {
		if !isFinalized(p, i) {
			return false
		}
	}
	return true
}

func (p *Pset) Locktime() uint32 {
	var heightLocktime, timeLocktime uint32
	for _, v := range p.Inputs {
		if v.RequiredTimeLocktime > 0 {
			if v.RequiredTimeLocktime > timeLocktime {
				timeLocktime = v.RequiredTimeLocktime
			}
		}
		if v.RequiredHeightLocktime > 0 {
			if v.RequiredHeightLocktime > heightLocktime {
				heightLocktime = v.RequiredHeightLocktime
			}
		}
	}

	if heightLocktime > 0 {
		return heightLocktime
	}

	if timeLocktime > 0 {
		return timeLocktime
	}

	return p.Global.FallbackLocktime
}

func (p *Pset) SanityCheck() error {
	var hasFullyBlindedOutput bool
	for i, in := range p.Inputs {
		if err := in.SanityCheck(); err != nil {
			return fmt.Errorf("invalid input %d: %s", i, err)
		}
	}
	for i, out := range p.Outputs {
		if err := out.SanityCheck(); err != nil {
			return fmt.Errorf("invalid output %d: %s", i, err)
		}
		if out.IsFullyBlinded() {
			hasFullyBlindedOutput = true
		}
	}

	if hasFullyBlindedOutput && len(p.Global.Scalars) == 0 && p.NeedsBlinding() {
		return ErrPsetInvalidGlobablModifiableState
	}

	return nil
}

func (p *Pset) UnsignedTx() (*transaction.Transaction, error) {
	tx := transaction.NewTx(int32(p.Global.TxVersion))
	tx.Locktime = p.Locktime()

	for _, in := range p.Inputs {
		txIn := transaction.NewTxInput(in.PreviousTxid, in.PreviousTxIndex)
		sequence := in.Sequence
		if sequence == 0 {
			sequence = transaction.DefaultSequence
		}
		txIn.Sequence = sequence
		if in.IssuanceAssetEntropy != nil {
			issuanceValue := in.IssuanceValueCommitment
			if issuanceValue == nil {
				issuanceValue, _ = elementsutil.ValueToBytes(in.IssuanceValue)
			}
			tokenValue := in.IssuanceInflationKeysCommitment
			if tokenValue == nil {
				tokenValue, _ = elementsutil.ValueToBytes(in.IssuanceInflationKeys)
			}
			txIn.Issuance = &transaction.TxIssuance{
				AssetEntropy:       in.IssuanceAssetEntropy,
				AssetBlindingNonce: in.IssuanceBlindingNonce,
				AssetAmount:        issuanceValue,
				TokenAmount:        tokenValue,
			}
		}

		tx.AddInput(txIn)
	}

	for _, out := range p.Outputs {
		value := out.ValueCommitment
		if value == nil {
			value, _ = elementsutil.ValueToBytes(out.Value)
		}
		asset := out.AssetCommitment
		if asset == nil {
			asset = append([]byte{0x01}, out.Asset...)
		}
		txOut := transaction.NewTxOutput(asset, value, out.Script)
		txOut.Script = out.Script
		txOut.RangeProof = out.ValueRangeproof
		txOut.SurjectionProof = out.AssetSurjectionProof
		if out.EcdhPubkey != nil {
			txOut.Nonce = out.EcdhPubkey
		}

		tx.AddOutput(txOut)
	}

	return tx, nil
}

func (p *Pset) ValidateAllSignatures() (bool, error) {
	for i := range p.Inputs {
		valid, err := p.ValidateInputSignatures(i)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, nil
		}
	}
	return true, nil
}

func (p *Pset) ValidateInputSignatures(
	inputIndex int,
) (bool, error) {
	if len(p.Inputs[inputIndex].PartialSigs) > 0 {
		for _, partialSig := range p.Inputs[inputIndex].PartialSigs {
			valid, err := p.validatePartialSignature(inputIndex, partialSig)
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

func (p *Pset) addInput(in Input) error {
	if err := in.SanityCheck(); err != nil {
		return err
	}
	if p.isDuplicateInput(in) {
		return ErrDuplicateKey
	}
	if !p.InputsModifiable() {
		return ErrPsetForbiddenInputsModification
	}
	if in.RequiredHeightLocktime != 0 || in.RequiredTimeLocktime != 0 {
		oldLocktime := p.Locktime()
		timeLocktime := in.RequiredTimeLocktime
		heightLocktime := in.RequiredHeightLocktime
		hasSigs := false
		for _, i := range p.Inputs {
			if i.RequiredTimeLocktime != 0 && i.RequiredHeightLocktime == 0 {
				heightLocktime = 0
				if timeLocktime == 0 {
					return ErrInInvalidLocktime
				}
			}
			if i.RequiredTimeLocktime == 0 && i.RequiredHeightLocktime != 0 {
				timeLocktime = 0
				if heightLocktime == 0 {
					return ErrInInvalidLocktime
				}
			}
			if i.RequiredTimeLocktime != 0 && timeLocktime != 0 {
				timeLocktime = max(timeLocktime, i.RequiredTimeLocktime)
			}
			if i.RequiredHeightLocktime != 0 && heightLocktime != 0 {
				heightLocktime = max(heightLocktime, i.RequiredHeightLocktime)
			}
			if len(i.PartialSigs) > 0 {
				hasSigs = true
			}
		}
		newLocktime := p.Global.FallbackLocktime
		if timeLocktime != 0 {
			newLocktime = timeLocktime
		}
		if heightLocktime != 0 {
			newLocktime = heightLocktime
		}
		if hasSigs && oldLocktime != newLocktime {
			return ErrInInvalidLocktime
		}
	}

	p.Inputs = append(p.Inputs, in)
	p.Global.InputCount++
	return nil
}

func (p *Pset) addOutput(out Output) error {
	if err := out.SanityCheck(); err != nil {
		return err
	}
	if !p.OutputsModifiable() {
		return ErrPsetForbiddenOutputsModification
	}

	p.Outputs = append(p.Outputs, out)
	p.Global.OutputCount++
	if out.IsBlinded() {
		p.Global.Modifiable.Set(0)
	}
	return nil
}

func (p *Pset) isDuplicateInput(in Input) bool {
	for _, i := range p.Inputs {
		if bytes.Equal(i.PreviousTxid, in.PreviousTxid) &&
			i.PreviousTxIndex == in.PreviousTxIndex {
			return true
		}
	}
	return false
}

func (p *Pset) validatePartialSignature(
	inputIndex int, partialSignature PartialSig,
) (bool, error) {
	if len(partialSignature.PubKey) == 0 {
		return false, ErrPartialSignatureMissingPubKey
	}

	signatureLen := len(partialSignature.Signature)
	sigHashType := partialSignature.Signature[signatureLen-1]
	signatureDer := partialSignature.Signature[:signatureLen-1]

	sigHash, script, err := p.getHashAndScriptForSignature(
		inputIndex, uint32(sigHashType),
	)
	if err != nil {
		return false, err
	}

	valid, err := p.verifyScriptForPubKey(script, partialSignature.PubKey)
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

	return pSig.Verify(sigHash, pubKey), nil
}

func (p *Pset) getHashAndScriptForSignature(
	inputIndex int, sigHashType uint32,
) ([]byte, []byte, error) {
	var hash [32]byte
	var script []byte

	unsignedTx, err := p.UnsignedTx()
	if err != nil {
		return nil, nil, err
	}
	sighash := txscript.SigHashType(sigHashType)

	input := p.Inputs[inputIndex]

	if input.NonWitnessUtxo != nil {
		prevoutHash := p.Inputs[inputIndex].PreviousTxid
		utxoHash := input.NonWitnessUtxo.TxHash()

		if !bytes.Equal(prevoutHash, utxoHash.CloneBytes()) {
			return nil, nil, ErrInInvalidNonWitnessUtxo
		}

		prevoutIndex := p.Inputs[inputIndex].PreviousTxIndex
		prevout := input.NonWitnessUtxo.Outputs[prevoutIndex]
		if input.RedeemScript != nil {
			script = input.RedeemScript
		} else {
			script = prevout.Script
		}

		switch address.GetScriptType(script) {

		case address.P2WshScript:
			if input.WitnessScript == nil {
				return nil, nil, fmt.Errorf(
					"segwit input needs witnessScript if not p2wpkh",
				)
			}
			hash = unsignedTx.HashForWitnessV0(
				inputIndex, input.WitnessScript, prevout.Value, sighash,
			)
			script = input.WitnessScript

		case address.P2WpkhScript:
			pay, err := payment.FromScript(script, nil, nil)
			if err != nil {
				return nil, nil, err
			}
			hash = unsignedTx.HashForWitnessV0(
				inputIndex, pay.Script, input.WitnessUtxo.Value, sighash,
			)
		default:
			var err error
			hash, err = unsignedTx.HashForSignature(
				inputIndex, script, sighash,
			)
			if err != nil {
				return nil, nil, err
			}
		}
	} else if input.WitnessUtxo != nil {
		if input.RedeemScript != nil {
			script = input.RedeemScript
		} else {
			script = input.WitnessUtxo.Script
		}
		switch address.GetScriptType(script) {

		case address.P2WpkhScript:
			pay, err := payment.FromScript(script, nil, nil)
			if err != nil {
				return nil, nil, err
			}
			hash = unsignedTx.HashForWitnessV0(
				inputIndex, pay.Script, input.WitnessUtxo.Value, sighash,
			)
		case address.P2WshScript:
			hash = unsignedTx.HashForWitnessV0(
				inputIndex, input.WitnessScript, input.WitnessUtxo.Value, sighash,
			)
			script = input.WitnessScript
		default:
			return nil, nil, fmt.Errorf("input has witnessUtxo but non-segwit script")
		}
	} else {
		return nil, nil, fmt.Errorf("need a utxo input item for signing")
	}

	return hash[:], script, nil
}

func (p *Pset) verifyScriptForPubKey(script, pubKey []byte) (bool, error) {
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
		scriptAsm, hex.EncodeToString(pk.SerializeCompressed()),
	) || strings.Contains(
		scriptAsm, hex.EncodeToString(pkHash),
	) {
		return true, nil
	}

	return false, nil
}

func (p *Pset) serialize() ([]byte, error) {
	s := bufferutil.NewSerializer(nil)

	if err := s.WriteSlice(magicPrefixWithSeparator); err != nil {
		return nil, err
	}

	if err := p.Global.serialize(s); err != nil {
		return nil, err
	}

	for _, v := range p.Inputs {
		if err := v.serialize(s); err != nil {
			return nil, err
		}
	}

	for _, v := range p.Outputs {
		if err := v.serialize(s); err != nil {
			return nil, err
		}
	}

	return s.Bytes(), nil
}

func deserialize(buf *bytes.Buffer) (*Pset, error) {
	d := bufferutil.NewDeserializer(buf)

	magic, err := d.ReadSlice(uint(len(magicPrefixWithSeparator)))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(magic, magicPrefixWithSeparator) {
		return nil, ErrInvalidMagicBytes
	}

	global := Global{}
	if err := global.deserialize(buf); err != nil {
		return nil, err
	}

	inputs := make([]Input, 0)
	for i := 0; i < int(global.InputCount); i++ {
		input := Input{}
		if err := input.deserialize(buf); err != nil {
			return nil, err
		}

		inputs = append(inputs, input)
	}

	outputs := make([]Output, 0)
	for i := 0; i < int(global.OutputCount); i++ {
		output := Output{}
		err := output.deserialize(buf)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, output)
	}

	newPset := &Pset{Global: global, Inputs: inputs, Outputs: outputs}
	if err := newPset.SanityCheck(); err != nil {
		return nil, err
	}

	return newPset, nil
}
