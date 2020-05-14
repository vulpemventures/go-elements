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
	"encoding/binary"
	"io"
	"sort"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/transaction"
)

// PInput is a struct encapsulating all the data that can be attached to any
// specific input of the PSBT.
type PInput struct {
	NonWitnessUtxo     *transaction.Transaction
	WitnessUtxo        *transaction.TxOutput
	PartialSigs        []*PartialSig
	SighashType        txscript.SigHashType
	RedeemScript       []byte
	WitnessScript      []byte
	Bip32Derivation    []*Bip32Derivation
	FinalScriptSig     []byte
	FinalScriptWitness []byte
	Unknowns           []*Unknown
}

// NewPsbtInput creates an instance of PsbtInput given either a nonWitnessUtxo
// or a witnessUtxo.
//
// NOTE: Only one of the two arguments should be specified, with the other
// being `nil`; otherwise the created PsbtInput object will fail IsSane()
// checks and will not be usable.
func NewPsbtInput(nonWitnessUtxo *transaction.Transaction,
	witnessUtxo *transaction.TxOutput) *PInput {

	return &PInput{
		NonWitnessUtxo:     nonWitnessUtxo,
		WitnessUtxo:        witnessUtxo,
		PartialSigs:        []*PartialSig{},
		SighashType:        0,
		RedeemScript:       nil,
		WitnessScript:      nil,
		Bip32Derivation:    []*Bip32Derivation{},
		FinalScriptSig:     nil,
		FinalScriptWitness: nil,
		Unknowns:           nil,
	}
}

// IsSane returns true only if there are no conflicting values in the Psbt
// PInput. It checks that witness and non-witness utxo entries do not both
// exist, and that witnessScript entries are only added to witness inputs.
func (pi *PInput) IsSane() bool {

	if pi.NonWitnessUtxo != nil && pi.WitnessUtxo != nil {
		return false
	}
	if pi.WitnessUtxo == nil && pi.WitnessScript != nil {
		return false
	}
	if pi.WitnessUtxo == nil && pi.FinalScriptWitness != nil {
		return false
	}

	return true
}

// deserialize attempts to deserialize a new PInput from the passed io.Reader.
func (pi *PInput) deserialize(r io.Reader) error {
	for {
		keyint, keydata, err := getKey(r)
		if err != nil {
			return err
		}
		if keyint == -1 {
			// Reached separator byte
			break
		}
		value, err := wire.ReadVarBytes(
			r, 0, MaxPsbtValueLength, "PSET value",
		)
		if err != nil {
			return err
		}

		switch InputType(keyint) {

		case NonWitnessUtxoType:
			if pi.NonWitnessUtxo != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}

			tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(value))
			if err != nil {
				return err
			}
			pi.NonWitnessUtxo = tx

		case WitnessUtxoType:
			if pi.WitnessUtxo != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			txout, err := readTxOut(value)
			if err != nil {
				return err
			}
			pi.WitnessUtxo = txout

		case PartialSigType:
			newPartialSig := PartialSig{
				PubKey:    keydata,
				Signature: value,
			}

			if !newPartialSig.checkValid() {
				return ErrInvalidPsbtFormat
			}

			// Duplicate keys are not allowed
			for _, x := range pi.PartialSigs {
				if bytes.Equal(x.PubKey, newPartialSig.PubKey) {
					return ErrDuplicateKey
				}
			}

			pi.PartialSigs = append(pi.PartialSigs, &newPartialSig)

		case SighashType:
			if pi.SighashType != 0 {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}

			// Bounds check on value here since the sighash type must be a
			// 32-bit unsigned integer.
			if len(value) != 4 {
				return ErrInvalidKeydata
			}

			shtype := txscript.SigHashType(
				binary.LittleEndian.Uint32(value),
			)
			pi.SighashType = shtype

		case RedeemScriptInputType:
			if pi.RedeemScript != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			pi.RedeemScript = value

		case WitnessScriptInputType:
			if pi.WitnessScript != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			pi.WitnessScript = value

		case Bip32DerivationInputType:
			if !validatePubkey(keydata) {
				return ErrInvalidPsbtFormat
			}
			master, derivationPath, err := readBip32Derivation(value)
			if err != nil {
				return err
			}

			// Duplicate keys are not allowed
			for _, x := range pi.Bip32Derivation {
				if bytes.Equal(x.PubKey, keydata) {
					return ErrDuplicateKey
				}
			}

			pi.Bip32Derivation = append(
				pi.Bip32Derivation,
				&Bip32Derivation{
					PubKey:               keydata,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)

		case FinalScriptSigType:
			if pi.FinalScriptSig != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}

			pi.FinalScriptSig = value

		case FinalScriptWitnessType:
			if pi.FinalScriptWitness != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}

			pi.FinalScriptWitness = value

		default:
			// A fall through case for any proprietary types.
			keyintanddata := []byte{byte(keyint)}
			keyintanddata = append(keyintanddata, keydata...)
			newUnknown := &Unknown{
				Key:   keyintanddata,
				Value: value,
			}

			// Duplicate key+keydata are not allowed
			for _, x := range pi.Unknowns {
				if bytes.Equal(x.Key, newUnknown.Key) &&
					bytes.Equal(x.Value, newUnknown.Value) {
					return ErrDuplicateKey
				}
			}

			pi.Unknowns = append(pi.Unknowns, newUnknown)
		}
	}

	return nil
}

// serialize attempts to serialize the target PInput into the passed io.Writer.
func (pi *PInput) serialize(w io.Writer) error {

	if !pi.IsSane() {
		return ErrInvalidPsbtFormat
	}

	if pi.NonWitnessUtxo != nil {
		buf, err := pi.NonWitnessUtxo.Serialize()
		if err != nil {
			return err
		}

		err = serializeKVPairWithType(w, uint8(NonWitnessUtxoType), nil, buf)
		if err != nil {
			return err
		}
	}
	if pi.WitnessUtxo != nil {
		buf, err := writeTxOut(pi.WitnessUtxo)
		if err != nil {
			return err
		}

		err = serializeKVPairWithType(w, uint8(WitnessUtxoType), nil, buf)
		if err != nil {
			return err
		}
	}

	if pi.FinalScriptSig == nil && pi.FinalScriptWitness == nil {
		sort.Sort(PartialSigSorter(pi.PartialSigs))
		for _, ps := range pi.PartialSigs {
			err := serializeKVPairWithType(
				w,
				uint8(PartialSigType), ps.PubKey,
				ps.Signature,
			)
			if err != nil {
				return err
			}
		}

		if pi.SighashType != 0 {
			var shtBytes [4]byte
			binary.LittleEndian.PutUint32(
				shtBytes[:], uint32(pi.SighashType),
			)

			err := serializeKVPairWithType(
				w, uint8(SighashType), nil, shtBytes[:],
			)
			if err != nil {
				return err
			}
		}

		if pi.RedeemScript != nil {
			err := serializeKVPairWithType(
				w, uint8(RedeemScriptInputType), nil,
				pi.RedeemScript,
			)
			if err != nil {
				return err
			}
		}

		if pi.WitnessScript != nil {
			err := serializeKVPairWithType(
				w, uint8(WitnessScriptInputType), nil,
				pi.WitnessScript,
			)
			if err != nil {
				return err
			}
		}

		sort.Sort(Bip32Sorter(pi.Bip32Derivation))
		for _, kd := range pi.Bip32Derivation {
			err := serializeKVPairWithType(
				w,
				uint8(Bip32DerivationInputType), kd.PubKey,
				SerializeBIP32Derivation(
					kd.MasterKeyFingerprint, kd.Bip32Path,
				),
			)
			if err != nil {
				return err
			}
		}
	}

	if pi.FinalScriptSig != nil {
		err := serializeKVPairWithType(
			w, uint8(FinalScriptSigType), nil, pi.FinalScriptSig,
		)
		if err != nil {
			return err
		}
	}

	if pi.FinalScriptWitness != nil {
		err := serializeKVPairWithType(
			w, uint8(FinalScriptWitnessType), nil, pi.FinalScriptWitness,
		)
		if err != nil {
			return err
		}
	}

	// Unknown is a special case; we don't have a key type, only a key and
	// a value field
	for _, kv := range pi.Unknowns {
		err := serializeKVpair(w, kv.Key, kv.Value)
		if err != nil {
			return err
		}
	}

	return nil
}
