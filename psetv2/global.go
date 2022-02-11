package psetv2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/wire"

	"github.com/vulpemventures/go-elements/internal/bufferutil"

	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
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
	GlobalProprietary      = 0xFC //BIP 174

	//Elements Proprietary types
	GlobalScalar     = 0x00
	GlobalModifiable = 0x01

	//78 byte serialized extended public key as defined by BIP 32.
	pubKeyLength = 78
)

var (
	ErrGlobalInvalidXPub               = fmt.Errorf("invalid global xpub")
	ErrGlobalInvalidXPubDerivationPath = fmt.Errorf("invalid global xpub derivation path length")
	ErrGlobalInvalidTxVersion          = fmt.Errorf("invalid global tx version length")
	ErrGlobalInvalidFallbackLocktime   = fmt.Errorf("invalid global fallback locktime length")
	ErrGlobalInvalidInputCount         = fmt.Errorf("invalid global input count length")
	ErrGlobalInvalidOutputCount        = fmt.Errorf("invalid global output count length")
	ErrGlobalInvalidTxModifiable       = fmt.Errorf("invalid global tx modifiable length")
	ErrGlobalInvalidVersion            = fmt.Errorf("invalid global version length")
	ErrGlobalInvalidScalar             = fmt.Errorf("invalid global scalar length")
	ErrGlobalInvalidModifiable         = fmt.Errorf("invalid global modifiable length")
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
	Xpub             []Xpub
	TxVersion        uint32
	FallbackLocktime uint32
	InputCount       uint64
	OutputCount      uint64
	TxModifiable     BitSet
	Version          uint32
	Scalars          [][]byte
	Modifiable       BitSet
	ProprietaryData  []ProprietaryData
	Unknowns         []KeyPair
}

func (g *Global) getKeyPairs() ([]KeyPair, error) {
	keyPairs := make([]KeyPair, 0)

	for _, xpub := range g.Xpub {
		xPubKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalXpub,
				KeyData: SerializeBIP32Derivation(
					xpub.MasterFingerprint,
					xpub.DerivationPath,
				),
			},
			Value: xpub.ExtendedKey,
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

	fallbackLocktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(fallbackLocktime, g.FallbackLocktime)
	fallbackLocktimeKeyPair := KeyPair{
		Key: Key{
			KeyType: GlobalFallbackLocktime,
			KeyData: nil,
		},
		Value: fallbackLocktime,
	}
	keyPairs = append(keyPairs, fallbackLocktimeKeyPair)

	inputCount := new(bytes.Buffer)
	if err := wire.WriteVarInt(inputCount, 0, uint64(g.InputCount)); err != nil {
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
	if err := wire.WriteVarInt(
		outputCount, 0, uint64(g.OutputCount),
	); err != nil {
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
			txModifiable, binary.LittleEndian, uint64(g.TxModifiable.Uint8()),
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

	for _, v := range g.Scalars {
		scalarKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(GlobalScalar, v),
			},
			Value: nil,
		}
		keyPairs = append(keyPairs, scalarKeyPair)
	}

	if g.Modifiable != nil {
		modifiable := new(bytes.Buffer)
		if err := binary.Write(
			modifiable, binary.LittleEndian, uint64(g.Modifiable.Uint8()),
		); err != nil {
			return nil, err
		}
		elementsTxModifiableKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(GlobalModifiable, nil),
			},
			Value: modifiable.Bytes(),
		}
		keyPairs = append(keyPairs, elementsTxModifiableKeyPair)
	}

	for _, v := range g.ProprietaryData {
		kp := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
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
			if len(kp.Key.KeyData) != pubKeyLength {
				return ErrGlobalInvalidXPub
			}
			// Parse xpub to make sure it's valid
			xpubStr := base58.Encode(kp.Key.KeyData)
			if _, err := hdkeychain.NewKeyFromString(xpubStr); err != nil {
				return err
			}

			if len(kp.Value) == 0 || len(kp.Value)%4 != 0 {
				return ErrGlobalInvalidXPubDerivationPath
			}

			master, derivationPath, err := readBip32Derivation(kp.Value)
			if err != nil {
				return fmt.Errorf("invalid gloabl bip32 derivation: %s", err)
			}

			g.Xpub = append(g.Xpub, Xpub{
				ExtendedKey:       kp.Key.KeyData,
				MasterFingerprint: master,
				DerivationPath:    derivationPath,
			})
		case GlobalTxVersion:
			if g.TxVersion != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 4 {
				return ErrGlobalInvalidTxVersion
			}
			g.TxVersion = binary.LittleEndian.Uint32(kp.Value)
		case GlobalFallbackLocktime:
			if g.FallbackLocktime != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 4 {
				return ErrGlobalInvalidFallbackLocktime
			}
			g.FallbackLocktime = binary.LittleEndian.Uint32(kp.Value)
		case GlobalInputCount:
			if g.InputCount != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 1 {
				return ErrGlobalInvalidInputCount
			}
			g.InputCount = uint64(kp.Value[0])
		case GlobalOutputCount:
			if g.OutputCount != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 1 {
				return ErrGlobalInvalidOutputCount
			}
			g.OutputCount = uint64(kp.Value[0])
		case GlobalTxModifiable:
			if g.TxModifiable != nil {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 1 {
				return ErrGlobalInvalidTxModifiable
			}
			var tm uint8
			buf := bytes.NewReader(kp.Value)
			if err := binary.Read(buf, binary.LittleEndian, tm); err != nil {
				return err
			}
			txModifiable, err := NewBitSetFromBuffer(byte(tm))
			if err != nil {
				return err
			}
			g.TxModifiable = txModifiable
		case GlobalVersion:
			if g.Version != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 4 {
				return ErrGlobalInvalidVersion
			}
			g.Version = binary.LittleEndian.Uint32(kp.Value)
		case GlobalProprietary:
			pd := ProprietaryData{}
			if err := pd.fromKeyPair(kp); err != nil {
				return err
			}

			if bytes.Equal(pd.Identifier, magicPrefix) {
				switch pd.Subtype {
				case GlobalScalar:
					scalar := pd.KeyData
					if len(scalar) != 32 {
						return ErrGlobalInvalidScalar
					}

					if g.Scalars == nil {
						g.Scalars = make([][]byte, 0)
					}

					g.Scalars = append(g.Scalars, scalar)
				case GlobalModifiable:
					if g.Modifiable != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 1 {
						return ErrGlobalInvalidModifiable
					}
					var etm uint8
					buf := bytes.NewReader(kp.Value)
					if err := binary.Read(buf, binary.LittleEndian, &etm); err != nil {
						return err
					}
					modifiable, err := NewBitSetFromBuffer(byte(etm))
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

	return nil
}

func stepToString(step uint32) string {
	if step < hdkeychain.HardenedKeyStart {
		return fmt.Sprintf("%d", step)
	}
	step -= hdkeychain.HardenedKeyStart
	return fmt.Sprintf("%d'", step)
}
