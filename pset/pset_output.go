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
	"io"
	"sort"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/psbt"
)

// POutput is a struct encapsulating all the data that can be attached
// to any specific output of the PSBT.
type POutput struct {
	RedeemScript    []byte
	WitnessScript   []byte
	Bip32Derivation []*psbt.Bip32Derivation
}

// NewPsbtOutput creates an instance of PsbtOutput; the three parameters
// redeemScript, witnessScript and Bip32Derivation are all allowed to be
// `nil`.
func NewPsbtOutput(redeemScript []byte, witnessScript []byte,
	bip32Derivation []*psbt.Bip32Derivation) *POutput {
	return &POutput{
		RedeemScript:    redeemScript,
		WitnessScript:   witnessScript,
		Bip32Derivation: bip32Derivation,
	}
}

// deserialize attempts to recode a new POutput from the passed io.Reader.
func (po *POutput) deserialize(r io.Reader) error {
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
			r, 0, psbt.MaxPsbtValueLength, "PSET value",
		)
		if err != nil {
			return err
		}

		switch OutputType(keyint) {

		case RedeemScriptOutputType:
			if po.RedeemScript != nil {
				return psbt.ErrDuplicateKey
			}
			if keydata != nil {
				return psbt.ErrInvalidKeydata
			}
			po.RedeemScript = value

		case WitnessScriptOutputType:
			if po.WitnessScript != nil {
				return psbt.ErrDuplicateKey
			}
			if keydata != nil {
				return psbt.ErrInvalidKeydata
			}
			po.WitnessScript = value

		case Bip32DerivationOutputType:
			if !validatePubkey(keydata) {
				return psbt.ErrInvalidKeydata
			}
			master, derivationPath, err := readBip32Derivation(value)
			if err != nil {
				return err
			}

			// Duplicate keys are not allowed
			for _, x := range po.Bip32Derivation {
				if bytes.Equal(x.PubKey, keydata) {
					return psbt.ErrDuplicateKey
				}
			}

			po.Bip32Derivation = append(po.Bip32Derivation,
				&psbt.Bip32Derivation{
					PubKey:               keydata,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)

		default:
			// Unknown type is allowed for inputs but not outputs.
			return psbt.ErrInvalidPsbtFormat
		}
	}

	return nil
}

// serialize attempts to write out the target POutput into the passed
// io.Writer.
func (po *POutput) serialize(w io.Writer) error {
	if po.RedeemScript != nil {
		err := serializeKVPairWithType(
			w, uint8(RedeemScriptOutputType), nil, po.RedeemScript,
		)
		if err != nil {
			return err
		}
	}
	if po.WitnessScript != nil {
		err := serializeKVPairWithType(
			w, uint8(WitnessScriptOutputType), nil, po.WitnessScript,
		)
		if err != nil {
			return err
		}
	}

	sort.Sort(psbt.Bip32Sorter(po.Bip32Derivation))
	for _, kd := range po.Bip32Derivation {
		err := serializeKVPairWithType(
			w,
			uint8(Bip32DerivationOutputType),
			kd.PubKey,
			psbt.SerializeBIP32Derivation(
				kd.MasterKeyFingerprint,
				kd.Bip32Path,
			),
		)
		if err != nil {
			return err
		}
	}

	return nil
}
