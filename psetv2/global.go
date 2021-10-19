package psetv2

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/wire"

	"github.com/vulpemventures/go-elements/internal/bufferutil"

	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
)

const (
	//Per output types: BIP 174, 370, 371
	PsbtGlobalUnsignedTx          = 0x00 //BIP 174
	PsbtGlobalXpub                = 0x01 //BIP 174
	PsbtGlobalTxVersion           = 0x02 //BIP 370
	PsbtGlobalFallbackLocktime    = 0x03 //BIP 370
	PsbtGlobalInputCount          = 0x04 //BIP 370
	PsbtGlobalOutputCount         = 0x05 //BIP 370
	PsbtGlobalTxModifiable        = 0x06 //BIP 370
	PsbtGlobalSighashSingleInputs = 0x07 //BIP 370
	PsbtGlobalVersion             = 0xFB //BIP 174
	PsbtGlobalProprietary         = 0xFC //BIP 174

	//Elements Proprietary types
	PsetElementsGlobalScalar       = 0x00
	PsetElementsGlobalTxModifiable = 0x01

	//78 byte serialized extended public key as defined by BIP 32.
	pubKeyLength = 78
)

var (
	ErrInvalidElementsTxModifiableValue = errors.New("invalid elements tx modifiable value")
	ErrInvalidXPub                      = errors.New("invalid xpub")
	ErrInvalidXPubDerivationPathLength  = errors.New("incorrect length of global xpub derivation data")
	ErrInvalidPsetVersion               = errors.New("incorrect pset version")
	ErrInvalidTxVersion                 = errors.New("incorrect tx version")
	ErrInvalidScalarLength              = errors.New("invalid scalar length")
)

type Global struct {
	// global transaction data
	txInfo TxInfo
	// the version number of this PSET. Must be present.
	version *uint32
	// a global map from extended public keys to the used key fingerprint and
	// derivation path as defined by BIP 32
	xPub []DerivationPathWithXPub
	// scalars used for blinding
	scalars [][]byte
	// elements tx modifiable flag
	elementsTxModifiableFlag *uint8
	// other proprietaryData fields
	proprietaryData []proprietaryData
	// unknowns global key-value pairs.
	unknowns []keyPair
}

// TxInfo represents global information about the transaction
type TxInfo struct {
	// Transaction version. Must be 2.
	version *uint32
	// Locktime to use if no inputs specify a minimum locktime to use.
	// May be omitted in which case it is interpreted as 0.
	fallBackLockTime *uint32
	// Number of inputs in the transaction
	// Not public. Users should not be able to mutate this directly
	// This will be automatically whenever pset inputs are added
	inputCount *uint64
	// Number of outputs in the transaction
	// Not public. Users should not be able to mutate this directly
	// This will be automatically whenever pset inputs are added
	outputCount *uint64
	// Flags indicating that the transaction may be modified.
	// May be omitted in which case it is interpreted as 0.
	txModifiable *uint8
}

// DerivationPathWithXPub global information about xpub keypair
type DerivationPathWithXPub struct {
	// extendedPubKey extended public key as defined by BIP 32
	extendedPubKey *hdkeychain.ExtendedKey
	//masterKeyFingerPrint master key fingerprint as defined by BIP 32
	masterKeyFingerPrint *uint32
	// derivationPath derivation path of the public key
	derivationPath []uint32
}

func (g *Global) serialize(s *bufferutil.Serializer) error {
	globalKeyPairs, err := g.getKeyPairs()
	if err != nil {
		return err
	}

	for _, v := range globalKeyPairs {
		if err := serializeKeyPair(v, s); err != nil {
			return err
		}
	}

	if err := s.WriteUint8(separator); err != nil {
		return err
	}

	return nil
}

func (g Global) getKeyPairs() ([]keyPair, error) {
	keyPairs := make([]keyPair, 0)

	for _, v := range g.xPub {
		xPubKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalXpub,
				keyData: SerializeBIP32Derivation(
					*v.masterKeyFingerPrint,
					v.derivationPath,
				),
			},
			value: base58.Decode(v.extendedPubKey.String()),
		}
		keyPairs = append(keyPairs, xPubKeyPair)
	}

	if g.txInfo.version != nil {
		globalTxVersion := make([]byte, 4)
		binary.LittleEndian.PutUint32(globalTxVersion, *g.txInfo.version)
		versionKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalTxVersion,
				keyData: nil,
			},
			value: globalTxVersion,
		}
		keyPairs = append(keyPairs, versionKeyPair)
	}

	if g.txInfo.fallBackLockTime != nil {
		fallBackLockTime := make([]byte, 4)
		binary.LittleEndian.PutUint32(fallBackLockTime, *g.txInfo.fallBackLockTime)
		fallBackLockTimeKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalFallbackLocktime,
				keyData: nil,
			},
			value: fallBackLockTime,
		}
		keyPairs = append(keyPairs, fallBackLockTimeKeyPair)
	}

	if g.txInfo.inputCount != nil {
		inputCount := new(bytes.Buffer)
		if err := wire.WriteVarInt(inputCount, 0, *g.txInfo.inputCount); err != nil {
			return nil, err
		}
		inputCountKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalInputCount,
				keyData: nil,
			},
			value: inputCount.Bytes(),
		}
		keyPairs = append(keyPairs, inputCountKeyPair)
	}

	if g.txInfo.outputCount != nil {
		outputCount := new(bytes.Buffer)
		if err := wire.WriteVarInt(outputCount, 0, *g.txInfo.outputCount); err != nil {
			return nil, err
		}
		outputCountKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalOutputCount,
				keyData: nil,
			},
			value: outputCount.Bytes(),
		}
		keyPairs = append(keyPairs, outputCountKeyPair)
	}

	if g.txInfo.txModifiable != nil {
		txModifiable := new(bytes.Buffer)
		if err := binary.Write(txModifiable, binary.LittleEndian, g.txInfo.txModifiable); err != nil {
			return nil, err
		}
		txModifiableKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalTxModifiable,
				keyData: nil,
			},
			value: txModifiable.Bytes(),
		}
		keyPairs = append(keyPairs, txModifiableKeyPair)
	}

	if g.version != nil {
		globalVersion := make([]byte, 4)
		binary.LittleEndian.PutUint32(globalVersion, *g.version)
		globalVersionKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalVersion,
				keyData: nil,
			},
			value: globalVersion,
		}
		keyPairs = append(keyPairs, globalVersionKeyPair)
	}

	for _, v := range g.scalars {
		scalarKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsGlobalScalar, v),
			},
			value: nil,
		}
		keyPairs = append(keyPairs, scalarKeyPair)
	}

	if g.elementsTxModifiableFlag != nil {
		elementsTxModifiableFlag := new(bytes.Buffer)
		if err := binary.Write(elementsTxModifiableFlag, binary.LittleEndian, g.elementsTxModifiableFlag); err != nil {
			return nil, err
		}
		elementsTxModifiableKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsGlobalTxModifiable, nil),
			},
			value: elementsTxModifiableFlag.Bytes(),
		}
		keyPairs = append(keyPairs, elementsTxModifiableKeyPair)
	}

	for _, v := range g.proprietaryData {
		kp := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(v.subtype, v.keyData),
			},
			value: v.value,
		}
		keyPairs = append(keyPairs, kp)
	}

	for _, v := range g.unknowns {
		keyPairs = append(keyPairs, v)
	}

	return keyPairs, nil
}

func deserializeGlobal(buf *bytes.Buffer) (*Global, error) {
	global := &Global{}
	kp := &keyPair{}

	//read bytes and do the deserialization until separator is found at the
	//end of global map
	for {
		if err := kp.deserialize(buf); err != nil {
			if err == ErrNoMoreKeyPairs {
				break
			}
			return nil, err
		}

		switch kp.key.keyType {
		case PsbtGlobalTxVersion:
			version := binary.LittleEndian.Uint32(kp.value)
			global.txInfo.version = &version
		case PsbtGlobalFallbackLocktime:
			fallBackLockTime := binary.LittleEndian.Uint32(kp.value)
			global.txInfo.fallBackLockTime = &fallBackLockTime
		case PsbtGlobalInputCount:
			tmp := make([]byte, 8)
			for i, v := range kp.value {
				tmp[i] = v
			}
			ic := binary.LittleEndian.Uint64(tmp)
			global.txInfo.inputCount = &ic
		case PsbtGlobalOutputCount:
			tmp := make([]byte, 8)
			for i, v := range kp.value {
				tmp[i] = v
			}

			oc := binary.LittleEndian.Uint64(tmp)
			global.txInfo.outputCount = &oc
		case PsbtGlobalTxModifiable:
			var tm uint8
			buf := bytes.NewReader(kp.value)
			if err := binary.Read(buf, binary.LittleEndian, tm); err != nil {
				return nil, err
			}

			global.txInfo.txModifiable = &tm
		case PsbtGlobalXpub:
			if len(kp.key.keyData) != pubKeyLength {
				return nil, ErrInvalidXPub
			}
			xpubStr := base58.Encode(kp.key.keyData)
			extendedPubKey, err := hdkeychain.NewKeyFromString(xpubStr)
			if err != nil {
				return nil, err
			}

			if len(kp.value) == 0 || len(kp.value)%4 != 0 {
				return nil, ErrInvalidXPubDerivationPathLength
			}

			master, derivationPath, err := readBip32Derivation(kp.value)
			if err != nil {
				return nil, err
			}

			global.xPub = append(global.xPub, DerivationPathWithXPub{
				extendedPubKey:       extendedPubKey,
				masterKeyFingerPrint: &master,
				derivationPath:       derivationPath,
			})

		case PsbtGlobalVersion:
			version := binary.LittleEndian.Uint32(kp.value)
			global.version = &version
		case PsbtGlobalProprietary:
			pd := &proprietaryData{}
			if err := pd.proprietaryDataFromKeyPair(*kp); err != nil {
				return nil, err
			}

			if bytes.Equal(pd.identifier, psetMagic) {
				switch pd.subtype {
				case PsetElementsGlobalScalar:
					scalar := pd.keyData
					if len(scalar) != 32 {
						return nil, ErrInvalidScalarLength
					}

					if global.scalars == nil {
						global.scalars = make([][]byte, 0)
					}

					global.scalars = append(global.scalars, scalar)
				case PsetElementsGlobalTxModifiable:
					elementsTxModifiable := pd.value
					if len(elementsTxModifiable) != 1 {
						return nil, ErrInvalidElementsTxModifiableValue
					}

					var etm uint8
					buf := bytes.NewReader(kp.value)
					if err := binary.Read(buf, binary.LittleEndian, &etm); err != nil {
						return nil, err
					}

					global.elementsTxModifiableFlag = &etm
				default:
					if global.proprietaryData == nil {
						global.proprietaryData = make([]proprietaryData, 0)
					}
					global.proprietaryData = append(global.proprietaryData, *pd)
				}
			}

		default:
			unknowns, err := deserializeUnknownKeyPairs(buf)
			if err != nil {
				return nil, err
			}
			global.unknowns = unknowns
		}

	}

	//check mandatory fields
	if global.version == nil && *global.version != 2 {
		return nil, ErrInvalidPsetVersion
	}
	if global.txInfo.version == nil && *global.txInfo.version == 0 {
		return nil, ErrInvalidTxVersion
	}

	if global.txInfo.inputCount == nil && *global.txInfo.inputCount == 0 {
		return nil, ErrInvalidTxVersion
	}

	if global.txInfo.outputCount == nil && *global.txInfo.outputCount == 0 {
		return nil, ErrInvalidTxVersion
	}

	return global, nil
}
