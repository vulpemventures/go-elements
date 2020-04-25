package transaction

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

//TxIssuance defines the type for Issuance field in TxInput
type TxIssuance struct {
	AssetBlindingNonce []byte
	AssetEntropy       []byte
	AssetAmount        []byte
	TokenAmonnt        []byte
}

// TxInput defines an elements transaction input.
type TxInput struct {
	Hash                chainhash.Hash
	Index               uint32
	Script              []byte
	Sequence            uint32
	Witness             [][]byte
	IsPegin             bool
	PeginWitness        [][]byte
	Issuance            TxIssuance
	IssuanceRangeProof  []byte
	InflationRangeProof []byte
}

// TxOutput defines an elements transaction output.
type TxOutput struct {
	Script          []byte
	Value           []byte
	Asset           []byte
	Nonce           []byte
	RangeProof      []byte
	SurjectionProof []byte
}

// Transaction defines an elements transaction message.
type Transaction struct {
	Version  int32
	Flag     int32
	Locktime uint32
	Inputs   []*TxInput
	Outputs  []*TxOutput
}

// AddInput adds a transaction input to the message.
func (tx *Transaction) AddInput(ti *TxInput) {
	tx.Inputs = append(tx.Inputs, ti)
}

// AddOutput adds a transaction output to the message.
func (tx *Transaction) AddOutput(to *TxOutput) {
	tx.Outputs = append(tx.Outputs, to)
}

func (tx *Transaction) hasWitness() bool {
	return true
}

// TxHash generates the Hash for the transaction.
func (tx *Transaction) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	buf := bytes.NewBuffer(make([]byte, 0))
	return chainhash.DoubleHashH(buf.Bytes())
}

// WitnessHash generates the hash of the transaction serialized according to
// the new witness serialization defined in BIP0141 and BIP0144. The final
// output is used within the Segregated Witness commitment of all the witnesses
// within a block. If a transaction has no witness data, then the witness hash,
// is the same as its txid.
func (tx *Transaction) WitnessHash() chainhash.Hash {
	if tx.hasWitness() {
		buf := bytes.NewBuffer(make([]byte, 0))
		return chainhash.DoubleHashH(buf.Bytes())
	}
	return tx.TxHash()
}
