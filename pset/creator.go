// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pset

import (
	"github.com/btcsuite/btcutil/psbt"
	"github.com/vulpemventures/go-elements/transaction"
)

// New on provision of an input and output 'skeleton' for the transaction, a
// new partially populated PSET. The populated pset will include the
// unsigned transaction, and the set of known inputs and outputs contained
// within the unsigned transaction.  The values of nLockTime and transaction
// version (must be 1 of 2) must be specified here. Note that the default
// nSequence value is wire.MaxTxInSequenceNum.
// Referencing the PSBT BIP, this function serves the roles of the Creator.
func New(inputs []*transaction.TxInput,
	outputs []*transaction.TxOutput, version int32, nLockTime uint32) (*Pset, error) {

	// Create the new struct; the input and output lists will be empty, the
	// unsignedTx object must be constructed and serialized, and that
	// serialization should be entered as the only entry for the
	// globalKVPairs list.
	//
	// Ensure that the version of the transaction is greater then our
	// minimum allowed transaction version. There must be one sequence
	// number per input.
	if version < psbt.MinTxVersion {
		return nil, psbt.ErrInvalidPsbtFormat
	}

	unsignedTx := transaction.NewTx(version)
	unsignedTx.Locktime = nLockTime
	for _, in := range inputs {
		unsignedTx.AddInput(transaction.NewTxInput(in.Hash, in.Index))
	}
	for _, out := range outputs {
		unsignedTx.AddOutput(out)
	}

	// The input and output lists are empty, but there is a list of those
	// two lists, and each one must be of length matching the unsigned
	// transaction; the unknown list can be nil.
	pInputs := make([]PInput, len(unsignedTx.Inputs))
	pOutputs := make([]POutput, len(unsignedTx.Outputs))

	// This new Psbt is "raw" and contains no key-value fields, so sanity
	// checking with c.Cpsbt.SanityCheck() is not required.
	return &Pset{
		UnsignedTx: unsignedTx,
		Inputs:     pInputs,
		Outputs:    pOutputs,
		Unknowns:   nil,
	}, nil
}
