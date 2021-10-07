package psetv2

import (
	"bytes"
	"encoding/binary"
	"errors"

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
	PsbtElementsGlobalScalar       = 0x00
	PsbtElementsGlobalTxModifiable = 0x01

	//78 byte serialized extended public key as defined by BIP 32.
	pubKeyLength = 78
)

var (
	ErrInvalidElementsTxModifiableValue = errors.New("invalid elements tx modifiable value")
	ErrInvalidXPub                      = errors.New("invalid xpub")
	ErrInvalidXPubDerivationPathLength  = errors.New("incorrect length of global xpub derivation data")
)

type Global struct {
	// global transaction data
	txInfo TxInfo
	// the version number of this PSET. Must be present.
	version uint32
	// a global map from extended public keys to the used key fingerprint and
	// derivation path as defined by BIP 32
	xPub []DerivationPathInfo
	// scalars used for blinding
	scalars [][32]byte
	// elements tx modifiable flag
	elementsTxModifiableFlag uint8
	// other proprietaryData fields
	proprietaryData []proprietaryData
	// unknowns global key-value pairs.
	unknowns []keyPair
}

// TxInfo represents global information about the transaction
type TxInfo struct {
	// Transaction version. Must be 2.
	version uint32
	// Locktime to use if no inputs specify a minimum locktime to use.
	// May be omitted in which case it is interpreted as 0.
	fallBackLockTime uint32
	// Number of inputs in the transaction
	// Not public. Users should not be able to mutate this directly
	// This will be automatically whenever pset inputs are added
	inputCount uint
	// Number of outputs in the transaction
	// Not public. Users should not be able to mutate this directly
	// This will be automatically whenever pset inputs are added
	outputCount uint
	// Flags indicating that the transaction may be modified.
	// May be omitted in which case it is interpreted as 0.
	txModifiable uint8
}

// DerivationPathInfo global information about xpub keypair
type DerivationPathInfo struct {
	// extendedPubKey extended public key as defined by BIP 32
	extendedPubKey *hdkeychain.ExtendedKey
	//masterKeyFingerPrint master key fingerprint as defined by BIP 32
	masterKeyFingerPrint [4]byte
	// derivationPath derivation path of the public key
	derivationPath []uint32
}

func deserializeGlobal(buf *bytes.Buffer) (*Global, error) {
	global := &Global{
		txInfo:          TxInfo{},
		xPub:            make([]DerivationPathInfo, 0),
		scalars:         make([][32]byte, 0),
		proprietaryData: make([]proprietaryData, 0),
	}
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
			global.txInfo.version = binary.LittleEndian.Uint32(kp.value)
		case PsbtGlobalFallbackLocktime:
			global.txInfo.fallBackLockTime = binary.LittleEndian.Uint32(kp.value)
		case PsbtGlobalInputCount:
			var ic uint8
			buf := bytes.NewReader(kp.value)
			if err := binary.Read(buf, binary.LittleEndian, &ic); err != nil {
				return nil, err
			}

			global.txInfo.inputCount = uint(ic)
		case PsbtGlobalOutputCount:
			var oc uint8
			buf := bytes.NewReader(kp.value)
			if err := binary.Read(buf, binary.LittleEndian, &oc); err != nil {
				return nil, err
			}

			global.txInfo.outputCount = uint(oc)
		case PsbtGlobalTxModifiable:
			var tm uint8
			buf := bytes.NewReader(kp.value)
			if err := binary.Read(buf, binary.LittleEndian, &tm); err != nil {
				return nil, err
			}

			global.txInfo.txModifiable = tm
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

			fingerprint := kp.value[:4]
			var arr [4]byte
			copy(arr[:], fingerprint[:])

			derivationPathBytes := kp.value[4:]
			derivationPath := make([]uint32, 0, len(derivationPathBytes)/4)
			for i := 0; i < len(derivationPathBytes); i = i + 3 {
				var child uint32
				buf := bytes.NewReader(kp.value)
				if err := binary.Read(buf, binary.LittleEndian, &child); err != nil {
					return nil, err
				}

				derivationPath = append(derivationPath, child)
			}

			global.xPub = append(global.xPub, DerivationPathInfo{
				extendedPubKey:       extendedPubKey,
				masterKeyFingerPrint: arr,
				derivationPath:       derivationPath,
			})

		case PsbtGlobalVersion:
			global.version = binary.LittleEndian.Uint32(kp.value)
		case PsbtGlobalProprietary:
			pd := &proprietaryData{}
			if err := pd.proprietaryDataFromKeyPair(*kp); err != nil {
				return nil, err
			}

			if bytes.Equal(pd.identifier, psetMagic) {
				switch pd.subtype {
				case PsbtElementsGlobalScalar:
					scalar := pd.keyData

					var arr [32]byte
					copy(arr[:], scalar[:])
					global.scalars = append(global.scalars, arr)
				case PsbtElementsGlobalTxModifiable:
					elementsTxModifiable := pd.value
					if len(elementsTxModifiable) != 1 {
						return nil, ErrInvalidElementsTxModifiableValue
					}

					var etm uint8
					buf := bytes.NewReader(kp.value)
					if err := binary.Read(buf, binary.LittleEndian, &etm); err != nil {
						return nil, err
					}

					global.elementsTxModifiableFlag = etm
				default:
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

	return global, nil
}
