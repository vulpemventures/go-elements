package transaction

import (
	"bytes"
	"encoding/hex"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
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
	defaultTxInOutAlloc       = 15

	//SighashRangeproof is a flag that means the rangeproofs should be included in the sighash.
	SighashRangeproof = 0x40
)

var (
	One = [32]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	Zero = [32]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	MaxConfidentialValue = []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
)

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
	if index != MinusOne {
		index &= OutpointIndexMask
	}
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
	size := 40 + bufferutil.VarSliceSerializeSize(in.Script)
	if in.HasAnyIssuance() {
		size += 64 + len(in.Issuance.AssetAmount) + len(in.Issuance.TokenAmount)
	}
	return size
}

// HasAnyIssuance returns whether the input contains an issuance
func (in *TxInput) HasAnyIssuance() bool {
	return in.Issuance != nil
}

// HasIssuance returns wheter the input contains a pure asset issuance
func (in *TxInput) HasIssuance() bool {
	return in.HasAnyIssuance() && !in.Issuance.IsReissuance()
}

// HasReissuance returns wheter the input contains a reissuance of an asset
func (in *TxInput) HasReissuance() bool {
	return in.HasAnyIssuance() && in.Issuance.IsReissuance()
}

// HasConfidentialIssuance returns whether the input contains a blinded issuance
func (in *TxInput) HasConfidentialIssuance() bool {
	return in.HasAnyIssuance() && len(in.IssuanceRangeProof) > 0
}

// TxWitness defines the witness for a TxIn. A witness is to be interpreted as
// a slice of byte slices, or a stack with one or many elements.
type TxWitness [][]byte

// SerializeSize returns the number of bytes it would take to serialize the the
// transaction input's witness.
func (tw TxWitness) SerializeSize() int {
	size := bufferutil.VarIntSerializeSize(uint64(len(tw)))
	for _, wit := range tw {
		size += bufferutil.VarSliceSerializeSize(wit)
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
	return len(out.Asset) + len(out.Value) + len(out.Nonce) + bufferutil.VarSliceSerializeSize(out.Script)
}

// IsConfidential returns whether the output is a confidential one
func (out *TxOutput) IsConfidential() bool {
	return len(out.Nonce) > 1
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
	d := bufferutil.NewDeserializer(buf)

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
			if index&OutpointIssuanceFlag == OutpointIssuanceFlag {
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
			if index&OutpointPeginFlag == OutpointPeginFlag {
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

// NewTxFromHex deserializes the given transaction in hex format and returns
// an instance of *Transaction.
func NewTxFromHex(str string) (*Transaction, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)
	return NewTxFromBuffer(buf)
}

// NewTx returns a new elements tx message. The return instance has no
// transaction inputs or outputs. Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewTx(version int32) *Transaction {
	return &Transaction{
		Version: version,
		Inputs:  make([]*TxInput, 0, defaultTxInOutAlloc),
		Outputs: make([]*TxOutput, 0, defaultTxInOutAlloc),
	}
}

// AddInput creates an input with the given hash and index and adds it
// to the transaction.
func (tx *Transaction) AddInput(ti *TxInput) {
	tx.Inputs = append(tx.Inputs, ti)
}

// AddOutput adds an output to the transaction.
func (tx *Transaction) AddOutput(to *TxOutput) {
	tx.Outputs = append(tx.Outputs, to)
}

// HasWitness returns wether the transaction contains witness data
func (tx *Transaction) HasWitness() bool {
	return tx.Flag == 1 || tx.anyWitnessInput() || tx.anyConfidentialOutput()
}

// TxHash generates the Hash for the transaction.
func (tx *Transaction) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	buf, _ := tx.serialize(nil, false, true, false, false)
	return chainhash.DoubleHashH(buf)
}

// WitnessHash generates the hash of the transaction serialized according to
// the new witness serialization defined in BIP0141 and BIP0144. The final
// output is used within the Segregated Witness commitment of all the witnesses
// within a block. If a transaction has no witness data, then the witness hash,
// is the same as its txid.
func (tx *Transaction) WitnessHash() chainhash.Hash {
	if tx.HasWitness() {
		buf, _ := tx.serialize(nil, true, true, false, false)
		return chainhash.DoubleHashH(buf)
	}
	return tx.TxHash()
}

// CountIssuances returns the number issuances contained in the transaction
// as the number of issuances, reissuances and the total (their sum).
func (tx *Transaction) CountIssuances() (issuances, reissuances, total int) {

	for _, in := range tx.Inputs {
		if in.HasIssuance() {
			issuances++
		}
		if in.HasReissuance() {
			reissuances++
		}
	}
	total = issuances + reissuances
	return
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
		if iss := input.Issuance; iss != nil {
			newInput.Issuance = &TxIssuance{
				AssetAmount:        copyBytes(iss.AssetAmount),
				AssetEntropy:       copyBytes(iss.AssetEntropy),
				AssetBlindingNonce: copyBytes(iss.AssetBlindingNonce),
				TokenAmount:        copyBytes(iss.TokenAmount),
			}
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
			size += bufferutil.VarSliceSerializeSize(txIn.IssuanceRangeProof)
			size += bufferutil.VarSliceSerializeSize(txIn.InflationRangeProof)
			size += txIn.Witness.SerializeSize()
			size += txIn.PeginWitness.SerializeSize()
		}
		for _, txOut := range tx.Outputs {
			size += bufferutil.VarSliceSerializeSize(txOut.SurjectionProof)
			size += bufferutil.VarSliceSerializeSize(txOut.RangeProof)
		}
	}

	return size
}

// Serialize returns the serialization of the transaction.
func (tx *Transaction) Serialize() ([]byte, error) {
	return tx.serialize(nil, true, false, false, false)
}

// HashForSignature returns the double sha256 hash of the serialization
// of the transaction in order to then produce a signature from it.
// The transaction is serialized in a different way depending on the
// hashType provided.
func (tx *Transaction) HashForSignature(
	inIndex int,
	prevoutScript []byte,
	hashType txscript.SigHashType,
) ([32]byte, error) {
	if inIndex >= len(tx.Inputs) {
		return One, nil
	}

	txCopy := tx.Copy()

	// SIGHASH_NONE: ignore all outputs (wildcard payee)
	if (hashType & 0x1f) == txscript.SigHashNone {
		txCopy.Outputs = []*TxOutput{}
		for i := range txCopy.Inputs {
			if i != inIndex {
				txCopy.Inputs[i].Sequence = 0
			}
		}
	} else {
		// SIGHASH_SINGLE: ignore all outputs, except at the same index
		if (hashType & 0x1f) == txscript.SigHashSingle {
			if inIndex >= len(tx.Outputs) {
				return One, nil
			}

			outs := txCopy.Outputs[:inIndex+1]
			txCopy.Outputs = outs

			for i := 0; i < inIndex; i++ {
				txCopy.Outputs[i].Asset = Zero[:]
				txCopy.Outputs[i].Nonce = Zero[:]
				txCopy.Outputs[i].Value = MaxConfidentialValue
				txCopy.Outputs[i].Script = []byte{}
			}

			for i := range txCopy.Inputs {
				if i != inIndex {
					txCopy.Inputs[i].Sequence = 0
				}
			}
		}
	}

	// SIGHASH_ANYONECANPAY: ignore inputs entirely
	if (hashType & txscript.SigHashAnyOneCanPay) == 1 {
		input := TxInput{
			Hash:                txCopy.Inputs[inIndex].Hash,
			Index:               txCopy.Inputs[inIndex].Index,
			Sequence:            txCopy.Inputs[inIndex].Sequence,
			Script:              prevoutScript,
			IsPegin:             txCopy.Inputs[inIndex].IsPegin,
			Witness:             txCopy.Inputs[inIndex].Witness,
			PeginWitness:        txCopy.Inputs[inIndex].PeginWitness,
			Issuance:            txCopy.Inputs[inIndex].Issuance,
			IssuanceRangeProof:  txCopy.Inputs[inIndex].IssuanceRangeProof,
			InflationRangeProof: txCopy.Inputs[inIndex].InflationRangeProof,
		}
		txCopy.Inputs = []*TxInput{&input}
	} else {
		// SIGHASH_ALL: only ignore input scripts
		for i := range txCopy.Inputs {
			script := []byte{}
			if i == inIndex {
				script = prevoutScript
			}
			txCopy.Inputs[i].Script = script
		}
	}

	shouldCalculateRangeProofsHash := (hashType & SighashRangeproof) != 0
	buf, err := txCopy.serialize(nil, false, true, true, shouldCalculateRangeProofsHash)
	if err != nil {
		return [32]byte{}, err
	}
	buf = append(buf, []byte{byte(hashType), 0x00, 0x00, 0x00}...)
	return chainhash.DoubleHashH(buf), nil
}

// HashForWitnessV0 returns the double sha256 hash of the serialization
// of the transaction following the BIP-0143 specification. This hash should
// then be used to produce a witness signatures for the given inIndex input.
func (tx *Transaction) HashForWitnessV0(inIndex int, prevoutScript []byte, value []byte, hashType txscript.SigHashType) [32]byte {
	shouldCalculateRangeProofsHash := (hashType & SighashRangeproof) != 0

	hashInputs := Zero
	hashSequences := Zero
	hashIssuances := Zero
	hashOutputs := Zero
	hashForRangeProofs := Zero

	// Inputs
	if (hashType & txscript.SigHashAnyOneCanPay) == 0 {
		hashInputs = calcTxInputsHash(tx.Inputs)
	}
	// Sequences
	if (hashType&txscript.SigHashAnyOneCanPay) == 0 &&
		(hashType&0x1f) != txscript.SigHashSingle &&
		(hashType&0x1f) != txscript.SigHashNone {
		hashSequences = calcTxSequencesHash(tx.Inputs)
	}
	// Issuances
	if (hashType & txscript.SigHashAnyOneCanPay) == 0 {
		hashIssuances = calcTxIssuancesHash(tx.Inputs)
	}
	// Outputs
	if (hashType&0x1f) != txscript.SigHashSingle &&
		(hashType&0x1f) != txscript.SigHashNone {
		hashOutputs = calcTxOutputsHash(tx.Outputs)
		if shouldCalculateRangeProofsHash {
			hashForRangeProofs = calcRangeProofsHash(tx.Outputs)
		}
	} else {
		if (hashType&0x1f) == txscript.SigHashSingle && inIndex < len(tx.Outputs) {
			hashOutputs = calcTxOutputsHash([]*TxOutput{tx.Outputs[inIndex]})
			if shouldCalculateRangeProofsHash {
				hashForRangeProofs = calcRangeProofsHash([]*TxOutput{tx.Outputs[inIndex]})
			}
		}
	}

	s, _ := bufferutil.NewSerializer(nil)
	input := tx.Inputs[inIndex]

	s.WriteUint32(uint32(tx.Version))
	s.WriteSlice(hashInputs[:])
	s.WriteSlice(hashSequences[:])
	s.WriteSlice(hashIssuances[:])
	s.WriteSlice(input.Hash[:])
	s.WriteUint32(input.Index)
	s.WriteVarSlice(prevoutScript)
	s.WriteSlice(value)
	s.WriteUint32(input.Sequence)
	if iss := input.Issuance; iss != nil {
		s.WriteSlice(iss.AssetBlindingNonce)
		s.WriteSlice(iss.AssetEntropy)
		s.WriteSlice(iss.AssetAmount)
		s.WriteSlice(iss.TokenAmount)
	}
	s.WriteSlice(hashOutputs[:])
	if shouldCalculateRangeProofsHash {
		s.WriteSlice(hashForRangeProofs[:])
	}
	s.WriteUint32(tx.Locktime)
	s.WriteUint32(uint32(hashType))

	return chainhash.DoubleHashH(s.Bytes())
}

// ToHex returns the serializarion of the transaction in hex enncoding format.
func (tx *Transaction) ToHex() (string, error) {
	bytes, err := tx.Serialize()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (tx *Transaction) anyWitnessInput() bool {
	for _, input := range tx.Inputs {
		if (input.Witness != nil && len(input.Witness) > 0) || (input.PeginWitness != nil && len(input.PeginWitness) > 0) {
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
	size := 8 + extraByte + bufferutil.VarIntSerializeSize(uint64(len(tx.Inputs))) +
		bufferutil.VarIntSerializeSize(uint64(len(tx.Outputs)))

	for _, txIn := range tx.Inputs {
		size += txIn.SerializeSize()
	}
	for _, txOut := range tx.Outputs {
		size += txOut.SerializeSize()
	}

	return size
}

func (tx *Transaction) serialize(
	buf *bytes.Buffer,
	allowWitness,
	zeroFlag,
	forSignature,
	withRangeProofs bool,
) ([]byte, error) {
	s, err := bufferutil.NewSerializer(buf)
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
		s.WriteSlice(txIn.Hash)
		index := txIn.Index
		issuance := txIn.Issuance
		if issuance != nil {
			index = (index | OutpointIssuanceFlag) >> 0
		}
		if txIn.IsPegin {
			index = (index | OutpointPeginFlag) >> 0
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
		if withRangeProofs {
			s.WriteVarSlice(txOut.RangeProof)
			s.WriteVarSlice(txOut.SurjectionProof)
		}
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

func calcTxInputsHash(ins []*TxInput) [32]byte {
	s, _ := bufferutil.NewSerializer(nil)
	for _, in := range ins {
		s.WriteSlice(in.Hash)
		s.WriteUint32(in.Index)
	}
	return chainhash.DoubleHashH(s.Bytes())
}

func calcTxSequencesHash(ins []*TxInput) [32]byte {
	s, _ := bufferutil.NewSerializer(nil)
	for _, in := range ins {
		s.WriteUint32(in.Sequence)
	}
	return chainhash.DoubleHashH(s.Bytes())
}

func calcTxIssuancesHash(ins []*TxInput) [32]byte {
	s, _ := bufferutil.NewSerializer(nil)
	for _, in := range ins {
		if iss := in.Issuance; iss != nil {
			s.WriteSlice(iss.AssetBlindingNonce)
			s.WriteSlice(iss.AssetEntropy)
			s.WriteSlice(iss.AssetAmount)
			s.WriteSlice(iss.TokenAmount)
		} else {
			s.WriteSlice([]byte{0x00})
		}
	}
	return chainhash.DoubleHashH(s.Bytes())
}

func calcTxOutputsHash(outs []*TxOutput) [32]byte {
	s, _ := bufferutil.NewSerializer(nil)
	for _, out := range outs {
		s.WriteSlice(out.Asset)
		s.WriteSlice(out.Value)
		s.WriteSlice(out.Nonce)
		s.WriteVarSlice(out.Script)
	}
	return chainhash.DoubleHashH(s.Bytes())
}

func calcRangeProofsHash(outs []*TxOutput) [32]byte {
	s, _ := bufferutil.NewSerializer(nil)
	for _, out := range outs {
		s.WriteVarSlice(out.RangeProof)
		s.WriteVarSlice(out.SurjectionProof)
	}
	return chainhash.DoubleHashH(s.Bytes())
}
