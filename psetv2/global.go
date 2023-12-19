package psetv2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/wire"

	"github.com/vulpemventures/go-elements/internal/bufferutil"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

const (
	//Per output types: BIP 174, 370, 371
	GlobalXpub             = 0x01 //BIP 174
	GlobalTxVersion        = 0x02 //BIP 370
	GlobalFallbackLocktime = 0x03 //BIP 370
	GlobalInputCount       = 0x04 //BIP 370
	GlobalOutputCount      = 0x05 //BIP 370
	GlobalTxModifiable     = 0x06 //BIP 370
	GlobalVersion          = 0xFB //BIP 174

	//Elements Proprietary types
	GlobalScalar     = 0x00
	GlobalModifiable = 0x01

	//78 byte serialized extended public key as defined by BIP 32.
	pubKeyLength = 78
)

var (
	ErrGlobalInvalidXPubLen               = fmt.Errorf("invalid global xpub value length")
	ErrGlobalInvalidXPubDerivationPathLen = fmt.Errorf("invalid global xpub derivation path value length")
	ErrGlobalInvalidTxVersionLen          = fmt.Errorf("invalid global tx version value length")
	ErrGlobalInvalidTxVersion             = fmt.Errorf("invalid global tx version value")
	ErrGlobalInvalidFallbackLocktimeLen   = fmt.Errorf("invalid global fallback locktime value length")
	ErrGlobalInvalidInputCountLen         = fmt.Errorf("invalid global input count value length")
	ErrGlobalInvalidOutputCountLen        = fmt.Errorf("invalid global output count value length")
	ErrGlobalInvalidTxModifiableLen       = fmt.Errorf("invalid global tx modifiable value length")
	ErrGlobalInvalidTxModifiable          = fmt.Errorf("invalid global tx modifiable value")
	ErrGlobalInvalidVersionLen            = fmt.Errorf("invalid global version value length")
	ErrGlobalInvalidVersion               = fmt.Errorf("invalid global version value")
	ErrGlobalInvalidScalarLen             = fmt.Errorf("invalid global scalar length")
	ErrGlobalInvalidModifiableLen         = fmt.Errorf("invalid global pset modifiable length")
	ErrGlobalInvalidModifiable            = fmt.Errorf("invalid global pset modifiable value")
	ErrGlobalDuplicatedField              = func(field string) error {
		return fmt.Errorf("duplicated global %s", field)
	}
)

type DerivationPath []uint32

func (p DerivationPath) String() string {
	if p == nil {
		return ""
	}
	path := "m/"
	for i, step := range p {
		val := stepToString(step)
		if i < len(p)-1 {
			val += "/"
		}
		path += val
	}
	return path
}

type Xpub struct {
	ExtendedKey       []byte
	MasterFingerprint uint32
	DerivationPath    DerivationPath
}

type Global struct {
	Xpubs            []Xpub
	TxVersion        uint32
	FallbackLocktime *uint32
	InputCount       uint64
	OutputCount      uint64
	TxModifiable     BitSet
	Version          uint32
	Scalars          [][]byte
	Modifiable       BitSet
	ProprietaryData  []ProprietaryData
	Unknowns         []KeyPair
}

func (g *Global) SanityCheck() error {
	if g.TxVersion < 2 {
		return ErrGlobalInvalidTxVersion
	}
	if g.Version != 2 {
		return ErrGlobalInvalidVersion
	}
	if findDuplicatedXpubs(g.Xpubs) {
		return ErrGlobalDuplicatedField("xpub")
	}
	if g.TxModifiable.Uint8() > 7 {
		return ErrGlobalInvalidTxModifiable
	}
	if g.Modifiable != nil && g.Modifiable.Uint8() != 0 {
		return ErrGlobalInvalidModifiable
	}
	if findDuplicatedScalars(g.Scalars) {
		return ErrGlobalDuplicatedField("scalar")
	}
	return nil
}

func (g *Global) getKeyPairs() ([]KeyPair, error) {
	keyPairs := make([]KeyPair, 0)

	for _, xpub := range g.Xpubs {
		keyData := append([]byte{byte(len(xpub.ExtendedKey))}, xpub.ExtendedKey...)
		xPubKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalXpub,
				KeyData: keyData,
			},
			Value: SerializeBIP32Derivation(
				xpub.MasterFingerprint,
				xpub.DerivationPath,
			),
		}
		keyPairs = append(keyPairs, xPubKeyPair)
	}

	txVersion := make([]byte, 4)
	binary.LittleEndian.PutUint32(txVersion, g.TxVersion)
	versionKeyPair := KeyPair{
		Key: Key{
			KeyType: GlobalTxVersion,
			KeyData: nil,
		},
		Value: txVersion,
	}
	keyPairs = append(keyPairs, versionKeyPair)

	if g.FallbackLocktime != nil {
		fallbackLocktime := make([]byte, 4)
		binary.LittleEndian.PutUint32(fallbackLocktime, *g.FallbackLocktime)
		fallbackLocktimeKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalFallbackLocktime,
				KeyData: nil,
			},
			Value: fallbackLocktime,
		}
		keyPairs = append(keyPairs, fallbackLocktimeKeyPair)
	}

	inputCount := new(bytes.Buffer)
	if err := wire.WriteVarInt(inputCount, 0, g.InputCount); err != nil {
		return nil, err
	}
	inputCountKeyPair := KeyPair{
		Key: Key{
			KeyType: GlobalInputCount,
			KeyData: nil,
		},
		Value: inputCount.Bytes(),
	}
	keyPairs = append(keyPairs, inputCountKeyPair)

	outputCount := new(bytes.Buffer)
	if err := wire.WriteVarInt(outputCount, 0, g.OutputCount); err != nil {
		return nil, err
	}
	outputCountKeyPair := KeyPair{
		Key: Key{
			KeyType: GlobalOutputCount,
			KeyData: nil,
		},
		Value: outputCount.Bytes(),
	}
	keyPairs = append(keyPairs, outputCountKeyPair)

	if g.TxModifiable != nil {
		txModifiable := new(bytes.Buffer)
		if err := binary.Write(
			txModifiable, binary.LittleEndian, g.TxModifiable.Uint8(),
		); err != nil {
			return nil, err
		}
		txModifiableKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalTxModifiable,
				KeyData: nil,
			},
			Value: txModifiable.Bytes(),
		}
		keyPairs = append(keyPairs, txModifiableKeyPair)
	}

	for _, v := range g.Scalars {
		scalarKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(GlobalScalar, v),
			},
			Value: nil,
		}
		keyPairs = append(keyPairs, scalarKeyPair)
	}

	globalVersion := make([]byte, 4)
	binary.LittleEndian.PutUint32(globalVersion, g.Version)
	globalVersionKeyPair := KeyPair{
		Key: Key{
			KeyType: GlobalVersion,
			KeyData: nil,
		},
		Value: globalVersion,
	}
	keyPairs = append(keyPairs, globalVersionKeyPair)

	if g.Modifiable != nil && g.Modifiable.Uint8() > 0 {
		modifiable := new(bytes.Buffer)
		if err := binary.Write(
			modifiable, binary.LittleEndian, g.Modifiable.Uint8(),
		); err != nil {
			return nil, err
		}
		elementsTxModifiableKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(GlobalModifiable, nil),
			},
			Value: modifiable.Bytes(),
		}
		keyPairs = append(keyPairs, elementsTxModifiableKeyPair)
	}

	for _, v := range g.ProprietaryData {
		kp := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(v.Subtype, v.KeyData),
			},
			Value: v.Value,
		}
		keyPairs = append(keyPairs, kp)
	}

	keyPairs = append(keyPairs, g.Unknowns...)

	return keyPairs, nil
}

func (g *Global) serialize(s *bufferutil.Serializer) error {
	globalKeyPairs, err := g.getKeyPairs()
	if err != nil {
		return err
	}

	for _, v := range globalKeyPairs {
		if err := v.serialize(s); err != nil {
			return err
		}
	}

	if err := s.WriteUint8(separator); err != nil {
		return err
	}

	return nil
}

func (g *Global) deserialize(buf *bytes.Buffer) error {
	kp := KeyPair{}

	//read bytes and do the deserialization until separator is found at the
	//end of global map
	for {
		if err := kp.deserialize(buf); err != nil {
			if err == ErrNoMoreKeyPairs {
				break
			}
			return err
		}

		switch kp.Key.KeyType {
		case GlobalXpub:
			if len(kp.Key.KeyData) != pubKeyLength+1 {
				return ErrGlobalInvalidXPubLen
			}

			if len(kp.Value) == 0 || len(kp.Value)%4 != 0 {
				return ErrGlobalInvalidXPubDerivationPathLen
			}

			master, derivationPath, err := readBip32Derivation(kp.Value)
			if err != nil {
				return fmt.Errorf("invalid gloabl bip32 derivation: %s", err)
			}

			g.Xpubs = append(g.Xpubs, Xpub{
				ExtendedKey:       kp.Key.KeyData[1:],
				MasterFingerprint: master,
				DerivationPath:    derivationPath,
			})
		case GlobalTxVersion:
			if g.TxVersion != 0 {
				return ErrGlobalDuplicatedField("tx version")
			}
			if len(kp.Value) != 4 {
				return ErrGlobalInvalidTxVersion
			}
			g.TxVersion = binary.LittleEndian.Uint32(kp.Value)
		case GlobalFallbackLocktime:
			if g.FallbackLocktime != nil {
				return ErrGlobalDuplicatedField("fallback locktime")
			}
			if len(kp.Value) != 4 {
				return ErrGlobalInvalidFallbackLocktimeLen
			}
			locktime := binary.LittleEndian.Uint32(kp.Value)
			g.FallbackLocktime = &locktime
		case GlobalInputCount:
			if g.InputCount != 0 {
				return ErrGlobalDuplicatedField("input count")
			}
			if len(kp.Value) != 1 {
				return ErrGlobalInvalidInputCountLen
			}
			g.InputCount = uint64(kp.Value[0])
		case GlobalOutputCount:
			if g.OutputCount != 0 {
				return ErrGlobalDuplicatedField("output count")
			}
			if len(kp.Value) != 1 {
				return ErrGlobalInvalidOutputCountLen
			}
			g.OutputCount = uint64(kp.Value[0])
		case GlobalTxModifiable:
			if g.TxModifiable != nil {
				return ErrGlobalDuplicatedField("tx modifiable")
			}
			if len(kp.Value) != 1 {
				return ErrGlobalInvalidTxModifiableLen
			}

			txModifiable, err := NewBitSetFromBuffer(byte(kp.Value[0]))
			if err != nil {
				return err
			}
			g.TxModifiable = txModifiable
		case GlobalVersion:
			if g.Version != 0 {
				return ErrGlobalDuplicatedField("version")
			}
			if len(kp.Value) != 4 {
				return ErrGlobalInvalidVersionLen
			}
			g.Version = binary.LittleEndian.Uint32(kp.Value)
		case PsetProprietary:
			pd := ProprietaryData{}
			if err := pd.fromKeyPair(kp); err != nil {
				return err
			}

			if bytes.Equal(pd.Identifier, magicPrefix) {
				switch pd.Subtype {
				case GlobalScalar:
					scalar := pd.KeyData
					if len(scalar) != 32 {
						return ErrGlobalInvalidScalarLen
					}

					if g.Scalars == nil {
						g.Scalars = make([][]byte, 0)
					}

					g.Scalars = append(g.Scalars, scalar)
				case GlobalModifiable:
					if g.Modifiable != nil {
						return ErrGlobalDuplicatedField("pset modifiable")
					}
					if len(kp.Value) != 1 {
						return ErrGlobalInvalidModifiableLen
					}
					modifiable, err := NewBitSetFromBuffer(byte(kp.Value[0]))
					if err != nil {
						return err
					}
					g.Modifiable = modifiable
				default:
					if g.ProprietaryData == nil {
						g.ProprietaryData = make([]ProprietaryData, 0)
					}
					g.ProprietaryData = append(g.ProprietaryData, pd)
				}
			}
		default:
			g.Unknowns = append(g.Unknowns, kp)
		}
	}

	return g.SanityCheck()
}

func stepToString(step uint32) string {
	if step < hdkeychain.HardenedKeyStart {
		return fmt.Sprintf("%d", step)
	}
	step -= hdkeychain.HardenedKeyStart
	return fmt.Sprintf("%d'", step)
}

func findDuplicatedXpubs(list []Xpub) bool {
	xpubs := make([]Xpub, len(list))
	copy(xpubs, list)
	for _, xpub := range xpubs {
		if len(xpubs) > 1 {
			next := xpubs[1:]
			for _, xp := range next {
				if bytes.Equal(xpub.ExtendedKey, xp.ExtendedKey) {
					return true
				}
			}
			xpubs = next
		}
	}
	return false
}

func findDuplicatedScalars(list [][]byte) bool {
	scalars := make([][]byte, len(list))
	copy(scalars, list)
	for _, scalar := range scalars {
		if len(scalars) > 1 {
			next := scalars[1:]
			for _, ss := range next {
				if bytes.Equal(scalar, ss) {
					return true
				}
			}
			scalars = next
		}
	}
	return false
}
