package psetv2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

const (
	//Per output types: BIP 174, 370, 371
	OutputRedeemScript       = 0x00 //BIP 174
	OutputWitnessScript      = 0x01 //BIP 174
	OutputBip32Derivation    = 0x02 //BIP 174
	OutputAmount             = 0x03 //BIP 370
	OutputScript             = 0x04 //BIP 370
	OutputTapInternalKey     = 0x05 //BIP 371
	OutputTapTree            = 0x06 //BIP 371
	OutputTapLeafScript      = 0x06 //BIP 371 //TODO is duplicate key type allowed?
	OutputTapBip32Derivation = 0x07 //BIP 371
	OutputProprietary        = 0xFC //BIP 174

	//Elements Proprietary types
	OutputValueCommitment      = 0x01
	OutputAsset                = 0x02
	OutputAssetCommitment      = 0x03
	OutputValueRangeproof      = 0x04
	OutputAssetSurjectionProof = 0x05
	OutputBlindingPubkey       = 0x06
	OutputEcdhPubkey           = 0x07
	OutputBlinderIndex         = 0x08
	OutputBlindValueProof      = 0x09
	OutputBlindAssetProof      = 0x0a
)

var (
	ErrOutInvalidBlinding = fmt.Errorf(
		"output is partially blinded while it must be either unblinded or " +
			"fully blinded",
	)
	ErrOutInvalidBlinderIndexState = fmt.Errorf(
		"blinder index must be unset for fully blinded output",
	)
	ErrOutInvalidValue          = fmt.Errorf("invalid output value length")
	ErrOutInvalidPubKey         = fmt.Errorf("invalid output pubkey length")
	ErrOutInvalidBlindingPubKey = fmt.Errorf(
		"invalid output blinding pubkey length",
	)
	ErrOutInvalidBlinderIndex = fmt.Errorf("invalid output blinder index length")
)

type Output struct {
	RedeemScript         []byte
	WitnessScript        []byte
	Bip32Derivation      []DerivationPathWithPubKey
	Value                uint64
	Script               []byte
	ValueCommitment      []byte
	Asset                []byte
	AssetCommitment      []byte
	ValueRangeproof      []byte
	AssetSurjectionProof []byte
	BlindingPubkey       []byte
	EcdhPubkey           []byte
	BlinderIndex         uint32
	BlindValueProof      []byte
	BlindAssetProof      []byte
	ProprietaryData      []ProprietaryData
	Unknowns             []KeyPair
}

func (o *Output) SanityCheck() error {
	if len(o.Asset) == 0 {
		return ErrOutMissingAsset
	}
	if o.IsBlinded() && o.IsPartiallyBlinded() && !o.IsFullyBlinded() {
		return ErrOutInvalidBlinding
	}
	if o.IsFullyBlinded() && o.BlinderIndex != 0 {
		return ErrOutInvalidBlinderIndexState
	}

	return nil
}

func (o *Output) IsBlinded() bool {
	return o.BlindingPubkey != nil
}

func (o *Output) IsPartiallyBlinded() bool {
	return o.IsBlinded() && (o.ValueCommitment != nil ||
		o.AssetCommitment != nil ||
		o.ValueRangeproof != nil ||
		o.AssetSurjectionProof != nil ||
		o.EcdhPubkey != nil)
}

func (o *Output) IsFullyBlinded() bool {
	return o.IsBlinded() && o.ValueCommitment != nil &&
		o.AssetCommitment != nil &&
		o.ValueRangeproof != nil &&
		o.AssetSurjectionProof != nil &&
		o.EcdhPubkey != nil
}

func (o *Output) getKeyPairs() ([]KeyPair, error) {
	keyPairs := make([]KeyPair, 0)

	if o.RedeemScript != nil {
		redeemScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: OutputRedeemScript,
				KeyData: nil,
			},
			Value: o.RedeemScript,
		}
		keyPairs = append(keyPairs, redeemScriptKeyPair)
	}

	if o.WitnessScript != nil {
		witnessScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: OutputWitnessScript,
				KeyData: nil,
			},
			Value: o.WitnessScript,
		}
		keyPairs = append(keyPairs, witnessScriptKeyPair)
	}

	if o.Bip32Derivation != nil {
		for _, v := range o.Bip32Derivation {
			bip32DerivationPathKeyPair := KeyPair{
				Key: Key{
					KeyType: OutputBip32Derivation,
					KeyData: v.PubKey,
				},
				Value: SerializeBIP32Derivation(v.MasterKeyFingerprint, v.Bip32Path),
			}
			keyPairs = append(keyPairs, bip32DerivationPathKeyPair)
		}
	}

	if o.Script != nil {
		outputScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: OutputScript,
				KeyData: nil,
			},
			Value: o.Script,
		}
		keyPairs = append(keyPairs, outputScriptKeyPair)
	}

	if o.ValueCommitment != nil {
		outputValueCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputValueCommitment, nil),
			},
			Value: o.ValueCommitment,
		}
		keyPairs = append(keyPairs, outputValueCommitmentKeyPair)
	}

	outputAmountBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(outputAmountBytes, o.Value)
	outputAmountKeyPair := KeyPair{
		Key: Key{
			KeyType: OutputAmount,
			KeyData: nil,
		},
		Value: outputAmountBytes,
	}
	keyPairs = append(keyPairs, outputAmountKeyPair)

	if o.AssetCommitment != nil {
		outputAssetCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputAssetCommitment, nil),
			},
			Value: o.AssetCommitment,
		}
		keyPairs = append(keyPairs, outputAssetCommitmentKeyPair)
	}

	if o.Asset != nil {
		outputAssetKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputAsset, nil),
			},
			Value: o.Asset,
		}
		keyPairs = append(keyPairs, outputAssetKeyPair)
	}

	if o.ValueRangeproof != nil {
		outputValueRangeproofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputValueRangeproof, nil),
			},
			Value: o.ValueRangeproof,
		}
		keyPairs = append(keyPairs, outputValueRangeproofKeyPair)
	}

	if o.AssetSurjectionProof != nil {
		outputAssetSurjectionProofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputAssetSurjectionProof, nil),
			},
			Value: o.AssetSurjectionProof,
		}
		keyPairs = append(keyPairs, outputAssetSurjectionProofKeyPair)
	}

	if o.BlindingPubkey != nil {
		outputBlindingPubkeyKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputBlindingPubkey, nil),
			},
			Value: o.BlindingPubkey,
		}
		keyPairs = append(keyPairs, outputBlindingPubkeyKeyPair)
	}

	if o.EcdhPubkey != nil {
		outputEcdhPubkeyKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputEcdhPubkey, nil),
			},
			Value: o.EcdhPubkey,
		}
		keyPairs = append(keyPairs, outputEcdhPubkeyKeyPair)
	}

	outputBlinderIndexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(outputBlinderIndexBytes, o.BlinderIndex)

	outputBlinderIndexKeyPair := KeyPair{
		Key: Key{
			KeyType: GlobalProprietary,
			KeyData: proprietaryKey(OutputBlinderIndex, nil),
		},
		Value: outputBlinderIndexBytes,
	}
	keyPairs = append(keyPairs, outputBlinderIndexKeyPair)

	if o.BlindValueProof != nil {
		outputBlindValueProofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputBlindValueProof, nil),
			},
			Value: o.BlindValueProof,
		}
		keyPairs = append(keyPairs, outputBlindValueProofKeyPair)
	}

	if o.BlindAssetProof != nil {
		outputBlindAssetProofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(OutputBlindAssetProof, nil),
			},
			Value: o.BlindAssetProof,
		}
		keyPairs = append(keyPairs, outputBlindAssetProofKeyPair)
	}

	for _, v := range o.ProprietaryData {
		kp := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(v.Subtype, v.KeyData),
			},
			Value: v.Value,
		}
		keyPairs = append(keyPairs, kp)
	}

	keyPairs = append(keyPairs, o.Unknowns...)

	return keyPairs, nil
}

func (o *Output) serialize(s *bufferutil.Serializer) error {
	outputKeyPairs, err := o.getKeyPairs()
	if err != nil {
		return err
	}

	for _, v := range outputKeyPairs {
		if err := v.serialize(s); err != nil {
			return err
		}
	}

	if err := s.WriteUint8(separator); err != nil {
		return err
	}

	return nil
}

func (o *Output) deserialize(buf *bytes.Buffer) error {
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
		case OutputRedeemScript:
			if o.RedeemScript != nil {
				return ErrDuplicateKey
			}
			o.RedeemScript = kp.Value
		case OutputWitnessScript:
			if o.WitnessScript != nil {
				return ErrDuplicateKey
			}
			o.WitnessScript = kp.Value
		case OutputBip32Derivation:
			if !validatePubkey(kp.Key.KeyData) {
				return ErrOutInvalidPubKey
			}
			master, derivationPath, err := readBip32Derivation(kp.Value)
			if err != nil {
				return fmt.Errorf("invalid output bip32 derivation: %s", err)
			}

			// Duplicate keys are not allowed
			for _, x := range o.Bip32Derivation {
				if bytes.Equal(x.PubKey, kp.Key.KeyData) {
					return ErrDuplicateKey
				}
			}

			o.Bip32Derivation = append(
				o.Bip32Derivation,
				DerivationPathWithPubKey{
					PubKey:               kp.Key.KeyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)
		case OutputAmount:
			if o.Value != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 8 {
				return ErrOutInvalidValue
			}
			o.Value = binary.LittleEndian.Uint64(kp.Value)
		case OutputScript:
			if o.Script != nil {
				return ErrDuplicateKey
			}
			o.Script = kp.Value
		case GlobalProprietary:
			pd := ProprietaryData{}
			if err := pd.fromKeyPair(kp); err != nil {
				return err
			}

			if bytes.Equal(pd.Identifier, magicPrefix[:len(magicPrefix)-1]) {
				switch pd.Subtype {
				case OutputValueCommitment:
					if o.ValueCommitment != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 33 {
						return ErrOutInvalidValueCommitment
					}
					o.ValueCommitment = kp.Value
				case OutputAsset:
					if o.Asset != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 32 {
						return ErrOutInvalidAsset
					}
					o.Asset = kp.Value
				case OutputAssetCommitment:
					if o.AssetCommitment != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 33 {
						return ErrOutInvalidAssetCommitment
					}
					o.AssetCommitment = kp.Value
				case OutputValueRangeproof:
					if o.ValueRangeproof != nil {
						return ErrDuplicateKey
					}
					o.ValueRangeproof = kp.Value
				case OutputAssetSurjectionProof:
					if o.AssetSurjectionProof != nil {
						return ErrDuplicateKey
					}
					o.AssetSurjectionProof = kp.Value
				case OutputBlindingPubkey:
					if o.BlindingPubkey != nil {
						return ErrDuplicateKey
					}
					if !validatePubkey(kp.Value) {
						return ErrOutInvalidBlindingPubKey
					}
					o.BlindingPubkey = kp.Value
				case OutputEcdhPubkey:
					if o.EcdhPubkey != nil {
						return ErrDuplicateKey
					}
					if !validatePubkey(kp.Value) {
						return ErrOutInvalidNonce
					}
					o.EcdhPubkey = kp.Value
				case OutputBlinderIndex:
					if o.BlinderIndex != 0 {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 4 {
						return ErrOutInvalidBlinderIndex
					}
					o.BlinderIndex = binary.LittleEndian.Uint32(kp.Value)
				case OutputBlindValueProof:
					if o.BlindValueProof != nil {
						return ErrDuplicateKey
					}
					o.BlindValueProof = kp.Value
				case OutputBlindAssetProof:
					if o.BlindAssetProof != nil {
						return ErrDuplicateKey
					}
					o.BlindAssetProof = kp.Value
				default:
					o.ProprietaryData = append(o.ProprietaryData, pd)
				}
			}
		default:
			o.Unknowns = append(o.Unknowns, kp)
		}
	}

	return o.SanityCheck()
}
