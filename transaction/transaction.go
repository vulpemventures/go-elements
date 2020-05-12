package transaction

import (
	"bytes"
	"encoding/hex"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	WitnessScaleFactor   = 4
	DefaultSequence      = 0xffffffff
	MinusOne             = 4294967295
	OutpointIndexMask    = 0x3fffffff
	OutpointIssuanceFlag = (1 << 31) >> 0
	OutpointPeginFlag    = (1 << 30) >> 0

	advancedTransactionFlag   = uint8(0x01)
	advancedTransactionMarker = uint8(0x00)
)

//TxIssuance defines the type for Issuance field in TxInput
type TxIssuance struct {
	AssetBlindingNonce []byte
	AssetEntropy       []byte
	AssetAmount        []byte
	TokenAmount        []byte
}

// TxInput defines an elements transaction input.
type TxInput struct {
	Hash                []byte
	Index               uint32
	Sequence            uint32
	Script              []byte
	Witness             TxWitness
	IsPegin             bool
	PeginWitness        TxWitness
	Issuance            *TxIssuance
	IssuanceRangeProof  []byte
	InflationRangeProof []byte
}

// NewTxInput returns a new input with given hash and index and a default max
// sequence number.
func NewTxInput(hash []byte, index uint32) *TxInput {
	return &TxInput{
		hash,
		index,
		DefaultSequence,
		nil,
		nil,
		false,
		nil,
		nil,
		nil,
		nil,
	}
}

// SerializeSize returns the number of bytes it would take to serialize the the
// transaction input.
func (in *TxInput) SerializeSize() int {
	size := 40 + varSliceSerializeSize(in.Script)
	if in.Issuance != nil {
		size += 64 + len(in.Issuance.AssetAmount) + len(in.Issuance.TokenAmount)
	}
	return size
}

// TxWitness defines the witness for a TxIn. A witness is to be interpreted as
// a slice of byte slices, or a stack with one or many elements.
type TxWitness [][]byte

// SerializeSize returns the number of bytes it would take to serialize the the
// transaction input's witness.
func (tw TxWitness) SerializeSize() int {
	size := varIntSerializeSize(uint64(len(tw)))
	for _, wit := range tw {
		size += varSliceSerializeSize(wit)
	}
	return size
}

// TxOutput defines an elements transaction output.
type TxOutput struct {
	Asset           []byte
	Value           []byte
	Script          []byte
	Nonce           []byte
	RangeProof      []byte
	SurjectionProof []byte
}

// NewTxOutput returns a new output with given asset, value and script and
// a default 0 nonce.
func NewTxOutput(asset, value, script []byte) *TxOutput {
	return &TxOutput{asset, value, script, []byte{0x00}, nil, nil}
}

// SerializeSize returns the number of bytes it would take to serialize the the
// transaction output.
func (out *TxOutput) SerializeSize() int {
	return len(out.Asset) + len(out.Value) + len(out.Nonce) + varSliceSerializeSize(out.Script)
}

// Transaction defines an elements transaction message.
type Transaction struct {
	Version  int32
	Flag     int32
	Locktime uint32
	Inputs   []*TxInput
	Outputs  []*TxOutput
}

// NewTxFromBuffer deserializes the given raw transaction in bytes and returns
// an instance of *Transaction.
func NewTxFromBuffer(buf *bytes.Buffer) (*Transaction, error) {
	d := NewDeserializer(buf)

	version, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}
	flag, err := d.ReadUint8()
	if err != nil {
		return nil, err
	}

	inputCount, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}
	inputs := []*TxInput{}
	for i := uint64(0); i < inputCount; i++ {
		hash, err := d.ReadSlice(32)
		if err != nil {
			return nil, err
		}
		index, err := d.ReadUint32()
		if err != nil {
			return nil, err
		}
		script, err := d.ReadVarSlice()
		if err != nil {
			return nil, err
		}
		sequence, err := d.ReadUint32()
		if err != nil {
			return nil, err
		}
		isPegin := false
		var issuance *TxIssuance
		if index != MinusOne {
			if (index & OutpointIssuanceFlag) == 1 {
				assetBlindingNonce, err := d.ReadSlice(32)
				if err != nil {
					return nil, err
				}
				assetEntropy, err := d.ReadSlice(32)
				if err != nil {
					return nil, err
				}
				assetAmount, err := d.ReadElementsValue()
				if err != nil {
					return nil, err
				}
				tokenAmount, err := d.ReadElementsValue()
				if err != nil {
					return nil, err
				}
				issuance = &TxIssuance{
					assetBlindingNonce,
					assetEntropy,
					assetAmount,
					tokenAmount,
				}
			}
			if (index & OutpointPeginFlag) == 1 {
				isPegin = true
			}
			index &= OutpointIndexMask
		}

		input := &TxInput{
			hash,
			index,
			sequence,
			script,
			nil,
			isPegin,
			nil,
			issuance,
			nil,
			nil,
		}
		inputs = append(inputs, input)
	}

	outputCount, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}
	outputs := []*TxOutput{}
	for i := uint64(0); i < outputCount; i++ {
		asset, err := d.ReadElementsAsset()
		if err != nil {
			return nil, err
		}
		value, err := d.ReadElementsValue()
		if err != nil {
			return nil, err
		}
		nonce, err := d.ReadElementsNonce()
		if err != nil {
			return nil, err
		}
		script, err := d.ReadVarSlice()
		if err != nil {
			return nil, err
		}

		output := &TxOutput{asset, value, script, nonce, nil, nil}
		outputs = append(outputs, output)
	}

	locktime, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}

	if flag == 1 {
		for _, input := range inputs {
			issuanceRangeProof, err := d.ReadVarSlice()
			if err != nil {
				return nil, err
			}
			inflationRangeProof, err := d.ReadVarSlice()
			if err != nil {
				return nil, err
			}
			witness, err := d.ReadVector()
			if err != nil {
				return nil, err
			}
			peginWitness, err := d.ReadVector()
			if err != nil {
				return nil, err
			}
			input.Witness = witness
			input.PeginWitness = peginWitness
			input.IssuanceRangeProof = issuanceRangeProof
			input.InflationRangeProof = inflationRangeProof
		}

		for _, output := range outputs {
			surjectionProof, err := d.ReadVarSlice()
			if err != nil {
				return nil, err
			}
			rangeProof, err := d.ReadVarSlice()
			if err != nil {
				return nil, err
			}

			output.SurjectionProof = surjectionProof
			output.RangeProof = rangeProof
		}
	}

	return &Transaction{int32(version), int32(flag), locktime, inputs, outputs}, nil
}

// NewTxFromString deserializes the given transaction in hex format and returns
// an instance of *Transaction.
func NewTxFromString(str string) (*Transaction, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)
	return NewTxFromBuffer(buf)
}

// AddInput creates an input with the given hash and index and adds it
// to the transaction.
func (tx *Transaction) AddInput(hash []byte, index uint32) error {
	// TODO:
	// err := checkInputData(hash, index)
	// if err != nil {
	// 	return err
	// }

	if index != MinusOne {
		index &= OutpointIndexMask
	}

	ti := NewTxInput(hash, index)
	tx.Inputs = append(tx.Inputs, ti)
	return nil
}

// AddOutput creates an output with the given asset, value and script and adds it
// to the transaction.
func (tx *Transaction) AddOutput(asset, value, script []byte) error {
	// TODO:
	// err := checkOutputData(asset, value, script)
	// if err != nil {
	// 	return err
	// }
	to := NewTxOutput(asset, value, script)
	tx.Outputs = append(tx.Outputs, to)
	return nil
}

// HasWitness returns wether the transaction contains witness data
func (tx *Transaction) HasWitness() bool {
	return tx.Flag == 1 || tx.anyWitnessInput() || tx.anyConfidentialOutput()
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
	if tx.HasWitness() {
		buf := bytes.NewBuffer(make([]byte, 0))
		return chainhash.DoubleHashH(buf.Bytes())
	}
	return tx.TxHash()
}

// Weight returns the total weight in bytes of the transaction
func (tx *Transaction) Weight() int {
	base := tx.SerializeSize(false, false)
	total := tx.SerializeSize(true, false)
	return base*(WitnessScaleFactor-1) + total
}

// VirtualSize returns the total weight of a transaction excluding witnesses
func (tx *Transaction) VirtualSize() int {
	return (tx.Weight() + WitnessScaleFactor - 1) / WitnessScaleFactor
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (tx *Transaction) Copy() *Transaction {
	newTx := Transaction{
		Version:  tx.Version,
		Flag:     tx.Flag,
		Inputs:   make([]*TxInput, 0, len(tx.Inputs)),
		Outputs:  make([]*TxOutput, 0, len(tx.Outputs)),
		Locktime: tx.Locktime,
	}
	copyBytes := func(src []byte) []byte {
		dst := make([]byte, len(src))
		copy(dst, src)
		return dst
	}

	for _, input := range tx.Inputs {
		hash := copyBytes(input.Hash)
		script := copyBytes(input.Script)
		newInput := TxInput{
			hash,
			input.Index,
			input.Sequence,
			script,
			nil,
			input.IsPegin,
			nil,
			nil,
			nil,
			nil,
		}
		if len(input.Witness) != 0 {
			newInput.Witness = make([][]byte, len(input.Witness))
			for i, wit := range input.Witness {
				newInput.Witness[i] = copyBytes(wit)
			}
		}
		if len(input.PeginWitness) != 0 {
			newInput.PeginWitness = make([][]byte, len(input.PeginWitness))
			for _, pwit := range input.PeginWitness {
				newInput.PeginWitness = append(newInput.PeginWitness, copyBytes(pwit))
			}
		}
		if len(input.IssuanceRangeProof) != 0 {
			newInput.IssuanceRangeProof = copyBytes(input.IssuanceRangeProof)
		}
		if len(input.InflationRangeProof) != 0 {
			newInput.InflationRangeProof = copyBytes(input.InflationRangeProof)
		}
		if input.Issuance != nil {
			newInput.Issuance.AssetAmount = copyBytes(input.Issuance.AssetAmount)
			newInput.Issuance.AssetEntropy = copyBytes(input.Issuance.AssetEntropy)
			newInput.Issuance.AssetBlindingNonce = copyBytes(input.Issuance.AssetBlindingNonce)
			newInput.Issuance.TokenAmount = copyBytes(input.Issuance.TokenAmount)
		}
		newTx.Inputs = append(newTx.Inputs, &newInput)
	}

	for _, output := range tx.Outputs {
		asset := copyBytes(output.Asset)
		value := copyBytes(output.Value)
		nonce := copyBytes(output.Nonce)
		script := copyBytes(output.Script)
		surjectionProof := copyBytes(output.SurjectionProof)
		rangeProof := copyBytes(output.RangeProof)

		newOutput := TxOutput{
			asset, value, script, nonce, rangeProof, surjectionProof,
		}
		newTx.Outputs = append(newTx.Outputs, &newOutput)
	}

	return &newTx
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction.
func (tx *Transaction) SerializeSize(allowWitness, forSignature bool) int {
	size := tx.baseSize(forSignature)

	if allowWitness && tx.HasWitness() {
		for _, txIn := range tx.Inputs {
			size += varSliceSerializeSize(txIn.IssuanceRangeProof)
			size += varSliceSerializeSize(txIn.InflationRangeProof)
			size += txIn.Witness.SerializeSize()
			size += txIn.PeginWitness.SerializeSize()
		}
		for _, txOut := range tx.Outputs {
			size += varSliceSerializeSize(txOut.SurjectionProof)
			size += varSliceSerializeSize(txOut.RangeProof)
		}
	}

	return size
}

// Serialize returns the serialization of the transaction.
func (tx *Transaction) Serialize() ([]byte, error) {
	return tx.serialize(nil, true, false, false)
}

// String returns the serializarion of the transaction in hex enncoding format.
func (tx *Transaction) String() (string, error) {
	bytes, err := tx.Serialize()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (tx *Transaction) anyWitnessInput() bool {
	for _, input := range tx.Inputs {
		if input.Witness != nil && len(input.Witness) > 0 {
			return true
		}
	}
	return false
}

func (tx *Transaction) anyConfidentialOutput() bool {
	for _, output := range tx.Outputs {
		if output.RangeProof != nil && len(output.RangeProof) > 0 {
			return true
		}
	}
	return false
}

func (tx *Transaction) baseSize(forSignature bool) int {
	extraByte := 0
	if !forSignature {
		extraByte = 1
	}
	size := 8 + extraByte + varIntSerializeSize(uint64(len(tx.Inputs))) +
		varIntSerializeSize(uint64(len(tx.Outputs)))

	for _, txIn := range tx.Inputs {
		size += txIn.SerializeSize()
	}
	for _, txOut := range tx.Outputs {
		size += txOut.SerializeSize()
	}

	return size
}

func (tx *Transaction) serialize(buf *bytes.Buffer, allowWitness, zeroFlag, forSignature bool) ([]byte, error) {
	s, err := NewSerializer(buf)
	if err != nil {
		return nil, err
	}

	// Version
	s.WriteUint32(uint32(tx.Version))

	hasWitnesses := allowWitness && tx.HasWitness()
	if !forSignature {
		value := advancedTransactionMarker
		if hasWitnesses && !zeroFlag {
			value = advancedTransactionFlag
		}
		s.WriteUint8(value)
	}

	// Inputs
	s.WriteVarInt(uint64(len(tx.Inputs)))
	for _, txIn := range tx.Inputs {
		s.WriteSlice(txIn.Hash[:])
		index := txIn.Index
		issuance := txIn.Issuance
		if !zeroFlag {
			if issuance != nil {
				index = (index | OutpointIssuanceFlag) >> 0
			}
			if txIn.IsPegin {
				index = (index | OutpointPeginFlag) >> 0
			}
		}
		s.WriteUint32(index)
		s.WriteVarSlice(txIn.Script)
		s.WriteUint32(txIn.Sequence)

		if issuance != nil {
			s.WriteSlice(issuance.AssetBlindingNonce)
			s.WriteSlice(issuance.AssetEntropy)
			s.WriteSlice(issuance.AssetAmount)
			s.WriteSlice(issuance.TokenAmount)
		}
	}

	// Outputs
	s.WriteVarInt(uint64(len(tx.Outputs)))
	for _, txOut := range tx.Outputs {
		s.WriteSlice(txOut.Asset)
		// Use Elements value format (bytes) for non confidential transactions
		if !(forSignature && hasWitnesses) {
			s.WriteSlice(txOut.Value)
		}
		s.WriteSlice(txOut.Nonce)
		// Use Bitcoin value format (uint) for confidential transactions
		if forSignature && hasWitnesses {
			s.WriteUint64(0)
		}
		s.WriteVarSlice(txOut.Script)
	}

	// Locktime
	s.WriteUint32(tx.Locktime)

	// Witnesses
	if !forSignature && hasWitnesses {
		// Input witnesses (includes confidential fields)
		for _, txIn := range tx.Inputs {
			s.WriteVarSlice(txIn.IssuanceRangeProof)
			s.WriteVarSlice(txIn.InflationRangeProof)
			s.WriteVector(txIn.Witness)
			s.WriteVector(txIn.PeginWitness)
		}
		// Output witnesses (includes confidential fields)
		for _, txOut := range tx.Outputs {
			s.WriteVarSlice(txOut.SurjectionProof)
			s.WriteVarSlice(txOut.RangeProof)
		}
	}

	return s.Bytes(), nil
}
