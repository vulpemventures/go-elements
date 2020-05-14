// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (c) 2019-2020 The VulpemVentures developers

// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.

// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
package pset

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/transaction"
)

// psbtMagicLength is the length of the magic bytes used to signal the start of
// a serialized PSBT packet.
const psbtMagicLength = 5

var (
	// psbtMagic is the separator
	psbtMagic = [psbtMagicLength]byte{0x70,
		0x73, 0x65, 0x74, 0xff, // = "pset" + 0xff sep
	}
)

// MaxPsbtValueLength is the size of the largest transaction serialization
// that could be passed in a NonWitnessUtxo field. This is definitely
//less than 4M.
const MaxPsbtValueLength = 4000000

// MaxPsbtKeyLength is the length of the largest key that we'll successfully
// deserialize from the wire. Anything more will return ErrInvalidKeydata.
const MaxPsbtKeyLength = 10000

var (
	// ErrInvalidPsbtFormat is a generic error for any situation in which a
	// provided Psbt serialization does not conform to the rules of BIP174.
	ErrInvalidPsbtFormat = errors.New("Invalid PSBT serialization format")

	// ErrDuplicateKey indicates that a passed Psbt serialization is invalid
	// due to having the same key repeated in the same key-value pair.
	ErrDuplicateKey = errors.New("Invalid Psbt due to duplicate key")

	// ErrInvalidKeydata indicates that a key-value pair in the PSBT
	// serialization contains data in the key which is not valid.
	ErrInvalidKeydata = errors.New("Invalid key data")

	// ErrInvalidMagicBytes indicates that a passed Psbt serialization is invalid
	// due to having incorrect magic bytes.
	ErrInvalidMagicBytes = errors.New("Invalid Psbt due to incorrect magic bytes")

	// ErrInvalidRawTxSigned indicates that the raw serialized transaction in the
	// global section of the passed Psbt serialization is invalid because it
	// contains scriptSigs/witnesses (i.e. is fully or partially signed), which
	// is not allowed by BIP174.
	ErrInvalidRawTxSigned = errors.New("Invalid Psbt, raw transaction must " +
		"be unsigned.")

	// ErrInvalidPrevOutNonWitnessTransaction indicates that the transaction
	// hash (i.e. SHA256^2) of the fully serialized previous transaction
	// provided in the NonWitnessUtxo key-value field doesn't match the prevout
	// hash in the UnsignedTx field in the PSBT itself.
	ErrInvalidPrevOutNonWitnessTransaction = errors.New("Prevout hash does " +
		"not match the provided non-witness utxo serialization")

	// ErrInvalidSignatureForInput indicates that the signature the user is
	// trying to append to the PSBT is invalid, either because it does
	// not correspond to the previous transaction hash, or redeem script,
	// or witness script.
	// NOTE this does not include ECDSA signature checking.
	ErrInvalidSignatureForInput = errors.New("Signature does not correspond " +
		"to this input")

	// ErrInputAlreadyFinalized indicates that the PSBT passed to a Finalizer
	// already contains the finalized scriptSig or witness.
	ErrInputAlreadyFinalized = errors.New("Cannot finalize PSBT, finalized " +
		"scriptSig or scriptWitnes already exists")

	// ErrIncompletePSBT indicates that the Extractor object
	// was unable to successfully extract the passed Psbt struct because
	// it is not complete
	ErrIncompletePSBT = errors.New("PSBT cannot be extracted as it is " +
		"incomplete")

	// ErrNotFinalizable indicates that the PSBT struct does not have
	// sufficient data (e.g. signatures) for finalization
	ErrNotFinalizable = errors.New("PSBT is not finalizable")

	// ErrInvalidSigHashFlags indicates that a signature added to the PSBT
	// uses Sighash flags that are not in accordance with the requirement
	// according to the entry in PsbtInSighashType, or otherwise not the
	// default value (SIGHASH_ALL)
	ErrInvalidSigHashFlags = errors.New("Invalid Sighash Flags")

	// ErrUnsupportedScriptType indicates that the redeem script or
	// scriptwitness given is not supported by this codebase, or is otherwise
	// not valid.
	ErrUnsupportedScriptType = errors.New("Unsupported script type")
)

// Unknown is a struct encapsulating a key-value pair for which the key type is
// unknown by this package; these fields are allowed in both the 'Global' and
// the 'Input' section of a PSET.
type Unknown struct {
	Key   []byte
	Value []byte
}

// Pset is the actual psbt repreesntation. It is a is a set of 1 + N + M
// key-value pair lists, 1 global, defining the unsigned transaction structure
// with N inputs and M outputs.  These key-value pairs can contain scripts,
// signatures, key derivations and other transaction-defining data.
type Pset struct {
	// UnsignedTx is the decoded unsigned transaction for this PSET.
	UnsignedTx *transaction.Transaction
	// Inputs contains all the information needed to properly sign this
	// target input within the above transaction.
	Inputs []PInput
	// Outputs contains all information required to spend any outputs
	// produced by this PSET.
	Outputs []POutput
	// Unknowns are the set of custom types (global only) within this PSET.
	Unknowns []Unknown // Data of unknown type at global scope
}

// validateUnsignedTx returns true if the transaction is unsigned.  Note that
// more basic sanity requirements, such as the presence of inputs and outputs,
// is implicitly checked in the call to MsgTx.Deserialize().
func validateUnsignedTX(tx *transaction.Transaction) bool {
	for _, tin := range tx.Inputs {
		if len(tin.Script) != 0 || len(tin.Witness) != 0 {
			return false
		}
	}

	return true
}

// isFinalized considers this input finalized if it contains at least one of
// the FinalScriptSig or FinalScriptWitness are filled (which only occurs in a
// successful call to Finalize*).
func isFinalized(p *Pset, inIndex int) bool {
	input := p.Inputs[inIndex]
	return input.FinalScriptSig != nil || input.FinalScriptWitness != nil
}

// deserialize returns a new instance of a Pset struct created by reading
// from a byte slice. If the format is invalid, an error is returned.
//
// NOTE: To create a Pset from one's own data, rather than reading in a
// serialization from a counterparty, one should use a pset.New.
func deserialize(r io.Reader) (*Pset, error) {
	// The Pset struct does not store the fixed magic bytes, but they
	// must be present or the serialization must be explicitly rejected.
	var magic [5]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != psbtMagic {
		return nil, ErrInvalidMagicBytes
	}

	// Next we parse the GLOBAL section.  There is currently only 1 known
	// key type, UnsignedTx.  We insist this exists first; unknowns are
	// allowed, but only after.
	keyint, keydata, err := getKey(r)
	if err != nil {
		return nil, err
	}
	if GlobalType(keyint) != UnsignedTxType || keydata != nil {
		return nil, ErrInvalidPsbtFormat
	}

	// Now that we've verified the global type is present, we'll decode it
	// into a proper unsigned transaction, and validate it.
	value, err := wire.ReadVarBytes(
		r, 0, MaxPsbtValueLength, "PSET value",
	)
	if err != nil {
		return nil, err
	}

	msgTx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(value))
	if err != nil {
		return nil, err
	}
	if !validateUnsignedTX(msgTx) {
		return nil, ErrInvalidRawTxSigned
	}

	// Next we parse any unknowns that may be present, making sure that we
	// break at the separator.
	var unknownSlice []Unknown
	for {
		keyint, keydata, err := getKey(r)
		if err != nil {
			return nil, ErrInvalidPsbtFormat
		}
		if keyint == -1 {
			break
		}

		value, err := wire.ReadVarBytes(
			r, 0, MaxPsbtValueLength, "PSET value",
		)
		if err != nil {
			return nil, err
		}

		keyintanddata := []byte{byte(keyint)}
		keyintanddata = append(keyintanddata, keydata...)

		newUnknown := Unknown{
			Key:   keyintanddata,
			Value: value,
		}
		unknownSlice = append(unknownSlice, newUnknown)
	}

	// Next we parse the INPUT section.
	inSlice := make([]PInput, len(msgTx.Inputs))
	for i := range msgTx.Inputs {
		input := PInput{}
		err = input.deserialize(r)
		if err != nil {
			return nil, err
		}

		inSlice[i] = input
	}

	// Next we parse the OUTPUT section.
	outSlice := make([]POutput, len(msgTx.Outputs))
	for i := range msgTx.Outputs {
		output := POutput{}
		err = output.deserialize(r)
		if err != nil {
			return nil, err
		}

		outSlice[i] = output
	}

	// Populate the new Packet object
	newPset := Pset{
		UnsignedTx: msgTx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		Unknowns:   unknownSlice,
	}

	// Extended sanity checking is applied here to make sure the
	// externally-passed Packet follows all the rules.
	if err = newPset.SanityCheck(); err != nil {
		return nil, err
	}

	return &newPset, nil
}

// NewPsetFromUnsignedTx creates a new Pset struct, without any signatures (i.e.
// only the global section is non-empty) using the passed unsigned transaction.
func NewPsetFromUnsignedTx(tx *transaction.Transaction) (*Pset, error) {
	if !validateUnsignedTX(tx) {
		return nil, ErrInvalidRawTxSigned
	}

	inSlice := make([]PInput, len(tx.Inputs))
	outSlice := make([]POutput, len(tx.Outputs))
	unknownSlice := make([]Unknown, 0)

	retPset := Pset{
		UnsignedTx: tx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		Unknowns:   unknownSlice,
	}

	return &retPset, nil
}

// NewPsetFromHex returns a new Pset from serialized pset in hex encoiding.
func NewPsetFromHex(psetHex string) (*Pset, error) {
	psetBytes, err := hex.DecodeString(psetHex)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(psetBytes)
	return deserialize(r)
}

// NewPsetFromBase64 returns a new Pset from a serialized pset in base64 encoding
func NewPsetFromBase64(psetBase64 string) (*Pset, error) {
	psetBytes, err := base64.StdEncoding.DecodeString(psetBase64)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(psetBytes)
	return deserialize(r)
}

// ToBase64 returns the base64 encoding of the serialization of
// the current PSET, or an error if the encoding fails.
func (p *Pset) ToBase64() (string, error) {
	buf, err := p.serialize()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf), nil
}

// ToHex returns the hex encoding of the serialization of
// the current PSET, or an error if the encoding fails.
func (p *Pset) ToHex() (string, error) {
	buf, err := p.serialize()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

// IsComplete returns true only if all of the inputs are
// finalized; this is particularly important in that it decides
// whether the final extraction to a network serialized signed
// transaction will be possible.
func (p *Pset) IsComplete() bool {
	for i := 0; i < len(p.UnsignedTx.Inputs); i++ {
		if !isFinalized(p, i) {
			return false
		}
	}
	return true
}

// SanityCheck checks conditions on a PSBT to ensure that it obeys the
// rules of BIP174, and returns true if so, false if not.
func (p *Pset) SanityCheck() error {

	if !validateUnsignedTX(p.UnsignedTx) {
		return ErrInvalidRawTxSigned
	}

	for _, tin := range p.Inputs {
		if !tin.IsSane() {
			return ErrInvalidPsbtFormat
		}
	}

	return nil
}

// Serialize creates a binary serialization of the referenced Pset struct
// with lexicographical ordering (by key) of the subsections.
func (p *Pset) serialize() ([]byte, error) {

	buffer := bytes.NewBuffer([]byte{})

	// First we write out the precise set of magic bytes that identify a
	// valid PSBT transaction.
	if _, err := buffer.Write(psbtMagic[:]); err != nil {
		return nil, err
	}

	// Next we prep to write out the unsigned transaction by first
	// serializing it into an intermediate buffer.
	serializedTx, err := p.UnsignedTx.Serialize()
	if err != nil {
		return nil, err
	}

	// Now that we have the serialized transaction, we'll write it out to
	// the proper global type.
	err = serializeKVPairWithType(
		buffer, uint8(UnsignedTxType), nil, serializedTx,
	)
	if err != nil {
		return nil, err
	}

	// With that our global section is done, so we'll write out the
	// separator.
	separator := []byte{0x00}
	if _, err := buffer.Write(separator); err != nil {
		return nil, err
	}

	for _, pInput := range p.Inputs {
		err := pInput.serialize(buffer)
		if err != nil {
			return nil, err
		}

		if _, err := buffer.Write(separator); err != nil {
			return nil, err
		}
	}

	for _, pOutput := range p.Outputs {
		err := pOutput.serialize(buffer)
		if err != nil {
			return nil, err
		}

		if _, err := buffer.Write(separator); err != nil {
			return nil, err
		}
	}

	return buffer.Bytes(), nil
}
