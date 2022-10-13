package psetv2

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	defaultVersion   = 2
	defaultTxVersion = 2
)

var (
	// Input errors
	ErrInMissingTxid       = fmt.Errorf("missing input txid")
	ErrInInvalidTxidFormat = fmt.Errorf("input txid must be in hex format")
	ErrInInvalidTxid       = fmt.Errorf("invalid input txid length")

	// Output errors
	ErrOutMissingAsset       = fmt.Errorf("missing output asset")
	ErrOutInvalidAssetFormat = fmt.Errorf("output asset must be in hex format")
	ErrOutInvalidAsset       = fmt.Errorf("invalid output asset length")
	ErrOutInvalidAddress     = fmt.Errorf("invalid output address")
)

type InputArgs struct {
	Txid       string
	TxIndex    uint32
	Sequence   uint32
	HeightLock uint32
	TimeLock   uint32
}

func (a InputArgs) validate() error {
	if a.Txid == "" {
		return ErrInMissingTxid
	}
	buf, err := hex.DecodeString(a.Txid)
	if err != nil {
		return ErrInInvalidTxidFormat
	}
	if len(buf) != 32 {
		return ErrInInvalidTxid
	}
	return nil
}

func (a InputArgs) toPartialInput() Input {
	txid, _ := hex.DecodeString(a.Txid)
	txid = elementsutil.ReverseBytes(txid)
	sequence := a.Sequence
	if sequence == 0 {
		sequence = transaction.DefaultSequence
	}
	return Input{
		PreviousTxid:           txid,
		PreviousTxIndex:        a.TxIndex,
		Sequence:               sequence,
		RequiredHeightLocktime: a.HeightLock,
		RequiredTimeLocktime:   a.TimeLock,
	}
}

type OutputArgs struct {
	Asset        string
	Amount       uint64
	Script       []byte
	BlindingKey  []byte
	BlinderIndex uint32
}

func (a OutputArgs) validate() error {
	if a.Asset == "" {
		return ErrOutMissingAsset
	}
	buf, err := hex.DecodeString(a.Asset)
	if err != nil {
		return ErrOutInvalidAssetFormat
	}
	if len(buf) != 32 {
		return ErrOutInvalidAsset
	}
	if len(a.Script) > 0 {
		if _, err := address.ParseScript(a.Script); err != nil {
			return fmt.Errorf("invalid output script: %s", err)
		}
	}
	if len(a.BlindingKey) > 0 {
		if _, err := btcec.ParsePubKey(a.BlindingKey); err != nil {
			return fmt.Errorf("invalid output blinding publick key: %s", err)
		}
	}
	return nil
}

func (a OutputArgs) toPartialOutput() Output {
	asset, _ := elementsutil.AssetHashToBytes(a.Asset)
	return Output{
		Value:          a.Amount,
		Asset:          asset[1:],
		Script:         a.Script,
		BlindingPubkey: a.BlindingKey,
		BlinderIndex:   a.BlinderIndex,
	}
}

func New(
	ins []InputArgs, outs []OutputArgs, locktime *uint32,
) (*Pset, error) {
	global := Global{
		Version:          defaultVersion,
		TxVersion:        defaultTxVersion,
		FallbackLocktime: locktime,
		Scalars:          make([][]byte, 0),
		ProprietaryData:  make([]ProprietaryData, 0),
		Unknowns:         make([]KeyPair, 0),
		Xpubs:            make([]Xpub, 0),
		TxModifiable:     NewBitSet(),
	}
	global.TxModifiable.Set(0)
	global.TxModifiable.Set(1)
	p := &Pset{
		Global:  global,
		Inputs:  make([]Input, 0),
		Outputs: make([]Output, 0),
	}

	for _, in := range ins {
		if err := p.addInput(in.toPartialInput()); err != nil {
			return nil, err
		}
	}

	for _, out := range outs {
		if err := p.addOutput(out.toPartialOutput()); err != nil {
			return nil, err
		}
	}

	return p, nil
}
