package psetv2

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcutil/psbt"

	"github.com/vulpemventures/go-elements/transaction"
)

const (
	separator         = 0x00
	maxPsbtKeyLength  = 10000
	minTimeLockTime   = 500000000
	maxHeightLockTime = 499999999
)

var (
	psetMagic                       = []byte{0x70, 0x73, 0x65, 0x74, 0xFF} //'pset' string with magic separator 0xFF
	ErrInvalidPsbtFormat            = errors.New("invalid PSBT serialization format")
	ErrNoMoreKeyPairs               = errors.New("no more key-pairs")
	ErrInvalidKeySize               = errors.New("invalid key size")
	ErrInvalidProprietaryKey        = errors.New("invalid proprietaryData key")
	ErrInvalidProprietaryIdentifier = errors.New("invalid proprietaryData identifier")
	ErrInvalidMagicBytes            = errors.New("invalid magic bytes")
	ErrNotModifiable                = errors.New("pset not modifiable")
	ErrInputAlreadyExist            = errors.New("input already exists")
	ErrInvalidLockTimeType          = errors.New("invalid locktime type")
	ErrInvalidLockTime              = errors.New("invalid lock time")
	ErrMissingMandatoryFields       = errors.New("missing mandatory fields")
	// ErrInvalidSignatureForInput indicates that the signature the user is
	// trying to append to the PSBT is invalid, either because it does
	// not correspond to the previous transaction hash, or redeem script,
	// or witness script.
	// NOTE this does not include ECDSA signature checking.
	ErrInvalidSignatureForInput = errors.New("Signature does not correspond " +
		"to this input")
)

// Pset - Partially signed Element's transaction
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
// Each map can contain proprietaryData data and unknowns keypair's
// Full spec: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
type Pset struct {
	Global  *Global
	Inputs  []Input
	Outputs []Output
}

func NewFromBuffer(buf *bytes.Buffer) (*Pset, error) {
	return deserialize(buf)
}

func NewFromHex(h string) (*Pset, error) {
	hexBytes, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(hexBytes)
	return NewFromBuffer(buf)
}

func NewPsetFromBase64(psetBase64 string) (*Pset, error) {
	psetBytes, err := base64.StdEncoding.DecodeString(psetBase64)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(psetBytes)
	return NewFromBuffer(buf)
}

func (p *Pset) ToBase64() (string, error) {
	buf, err := p.serialize()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf), nil
}

func (p *Pset) ToHex() (string, error) {
	buf, err := p.serialize()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

type InputArg struct {
	TimeLock *TimeLock
	TxInput  transaction.TxInput
}

func (p *Pset) addInput(inputArg InputArg) error {
	if p.IsInputModifiable() {
		return ErrNotModifiable
	}

	if p.IsInputDuplicate(inputArg.TxInput) {
		return ErrInputAlreadyExist
	}

	input, err := psetInputFromTxInput(inputArg.TxInput)
	if err != nil {
		return err
	}

	if inputArg.TimeLock.RequiredTimeLock != nil {
		input.requiredTimeLocktime = inputArg.TimeLock.RequiredTimeLock
	}
	if inputArg.TimeLock.RequiredHeightTimeLock != nil {
		input.requiredHeightLocktime = inputArg.TimeLock.RequiredHeightTimeLock
	}

	if input != nil {
		if err := p.validateInputTimeLock(*input); err != nil {
			return err
		}

		p.Inputs = append(p.Inputs, *input)
		*p.Global.txInfo.inputCount++
	}

	return nil
}

type OutputArg struct {
	BlinderIndex   uint32
	BlindingPubKey []byte
	TxOutput       transaction.TxOutput
}

func (p *Pset) addOutput(outputArg OutputArg) error {
	if p.IsOutputModifiable() {
		return ErrNotModifiable
	}

	output, err := psetOutputFromTxOutput(outputArg.TxOutput)
	if err != nil {
		return err
	}

	if output != nil {
		if output.outputAmount == nil || output.outputScript == nil {
			return ErrMissingMandatoryFields
		}

		if outputArg.BlindingPubKey != nil {
			p.BlindingNeeded()
			output.outputBlindingPubkey = outputArg.BlindingPubKey
			output.outputBlinderIndex = &outputArg.BlinderIndex
		}

		p.Outputs = append(p.Outputs, *output)
		*p.Global.txInfo.outputCount++
	}

	return nil
}

func (p *Pset) LockForModification() {
	var lockedForModification uint8 = 0 //0000 0000
	p.Global.txInfo.txModifiable = &lockedForModification
}

func (p *Pset) BlindingNeeded() {
	var blindingNeeded uint8 = 1 //0000 0001
	p.Global.elementsTxModifiableFlag = &blindingNeeded
}

func (p *Pset) IsInputModifiable() bool {
	if p.Global.txInfo.txModifiable == nil {
		return true
	}

	return *p.Global.txInfo.txModifiable&1 == 1 // 0000 0001
}

func (p *Pset) IsInputDuplicate(txInput transaction.TxInput) bool {
	for _, v := range p.Inputs {
		if *v.previousOutputIndex == txInput.Index && bytes.Equal(v.previousTxid, txInput.Hash) {
			return true
		}
	}

	return false
}

func (p *Pset) IsOutputModifiable() bool {
	if p.Global.txInfo.txModifiable == nil {
		return true
	}

	return *p.Global.txInfo.txModifiable&2 == 1 // 0000 0010
}

func (p *Pset) ComputeTimeLock() *uint32 {
	var heightLockTime uint32
	var timeLockTime uint32
	for _, v := range p.Inputs {
		if v.requiredTimeLocktime != nil {
			if *v.requiredTimeLocktime > timeLockTime {
				timeLockTime = *v.requiredTimeLocktime
			}
		}
		if v.requiredHeightLocktime != nil {
			if *v.requiredHeightLocktime > heightLockTime {
				heightLockTime = *v.requiredHeightLocktime
			}
		}
	}

	if heightLockTime > 0 {
		return &heightLockTime
	}

	if timeLockTime > 0 {
		return &timeLockTime
	}

	if p.Global.txInfo.fallBackLockTime != nil {
		return p.Global.txInfo.fallBackLockTime
	}

	return nil
}

// OwnerProvidedOutputBlindingInfo verifies if owner of the input/output provided
//necessary output blinding
func (p *Pset) OwnerProvidedOutputBlindingInfo(blinderIndex int) bool {
	var bi = uint32(blinderIndex)
	for _, v := range p.Outputs {
		if v.outputBlinderIndex != nil {
			if *v.outputBlinderIndex == bi {
				return v.outputBlindingPubkey != nil
			}
		}
	}

	return false
}

func (p *Pset) validateInputTimeLock(input Input) error {
	var timeLocktime uint32
	var heightLocktime uint32
	hasSigs := false
	if input.requiredTimeLocktime != nil || input.requiredHeightLocktime != nil {
		oldTimeLock := p.ComputeTimeLock()
		for _, v := range p.Inputs {
			if v.requiredTimeLocktime != nil && v.requiredHeightLocktime == nil {
				if input.requiredTimeLocktime == nil {
					return ErrInvalidLockTimeType
				}
			}

			if v.requiredTimeLocktime == nil && v.requiredHeightLocktime != nil {
				if input.requiredHeightLocktime == nil {
					return ErrInvalidLockTimeType
				}
			}

			if v.requiredTimeLocktime != nil && input.requiredTimeLocktime != nil {
				timeLocktime = *v.requiredTimeLocktime
			}

			if v.requiredHeightLocktime != nil && input.requiredHeightLocktime != nil {
				heightLocktime = *v.requiredHeightLocktime
			}

			if v.partialSigs != nil {
				hasSigs = true
			}
		}

		var newTimeLock uint32
		if p.Global.txInfo.fallBackLockTime != nil {
			newTimeLock = *p.Global.txInfo.fallBackLockTime
		}

		if heightLocktime > 0 {
			newTimeLock = heightLocktime
		}

		if timeLocktime > 0 {
			newTimeLock = timeLocktime
		}

		if oldTimeLock != nil {
			if hasSigs && *oldTimeLock != newTimeLock {
				return ErrInvalidLockTime
			}
		}
	}

	return nil
}

func (p *Pset) SanityCheck() error {
	for _, tin := range p.Inputs {
		if !tin.IsSane() {
			return psbt.ErrInvalidPsbtFormat
		}
	}

	return nil
}
