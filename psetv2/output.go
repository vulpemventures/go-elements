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
	return len(o.BlindingPubkey) > 0
}

func (o *Output) IsPartiallyBlinded() bool {
	return o.IsBlinded() && (len(o.ValueCommitment) > 0 ||
		len(o.AssetCommitment) > 0 ||
		len(o.ValueRangeproof) > 0 ||
		len(o.AssetSurjectionProof) > 0 ||
		len(o.EcdhPubkey) > 0)
}

func (o *Output) IsFullyBlinded() bool {
	return o.IsBlinded() && len(o.ValueCommitment) > 0 &&
		len(o.AssetCommitment) > 0 &&
		len(o.ValueRangeproof) > 0 &&
		len(o.AssetSurjectionProof) > 0 &&
		len(o.EcdhPubkey) > 0
}

func (o *Output) getKeyPairs() ([]KeyPair, error) {
	keyPairs := make([]KeyPair, 0)

	if len(o.RedeemScript) > 0 {
		redeemScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: OutputRedeemScript,
				KeyData: nil,
			},
			Value: o.RedeemScript,
		}
		keyPairs = append(keyPairs, redeemScriptKeyPair)
	}

	if len(o.WitnessScript) > 0 {
		witnessScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: OutputWitnessScript,
				KeyData: nil,
			},
			Value: o.WitnessScript,
		}
		keyPairs = append(keyPairs, witnessScriptKeyPair)
	}

	if len(o.Bip32Derivation) > 0 {
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

	outputScriptKeyPair := KeyPair{
		Key: Key{
			KeyType: OutputScript,
			KeyData: nil,
		},
		Value: o.Script,
	}
	keyPairs = append(keyPairs, outputScriptKeyPair)

	if len(o.ValueCommitment) > 0 {
		outputValueCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
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

	if len(o.AssetCommitment) > 0 {
		outputAssetCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(OutputAssetCommitment, nil),
			},
			Value: o.AssetCommitment,
		}
		keyPairs = append(keyPairs, outputAssetCommitmentKeyPair)
	}

	if len(o.Asset) > 0 {
		outputAssetKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(OutputAsset, nil),
			},
			Value: o.Asset,
		}
		keyPairs = append(keyPairs, outputAssetKeyPair)
	}

	if len(o.ValueRangeproof) > 0 {
		outputValueRangeproofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(OutputValueRangeproof, nil),
			},
			Value: o.ValueRangeproof,
		}
		keyPairs = append(keyPairs, outputValueRangeproofKeyPair)
	}

	if len(o.AssetSurjectionProof) > 0 {
		outputAssetSurjectionProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(OutputAssetSurjectionProof, nil),
			},
			Value: o.AssetSurjectionProof,
		}
		keyPairs = append(keyPairs, outputAssetSurjectionProofKeyPair)
	}

	if len(o.BlindingPubkey) > 0 {
		outputBlindingPubkeyKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(OutputBlindingPubkey, nil),
			},
			Value: o.BlindingPubkey,
		}
		keyPairs = append(keyPairs, outputBlindingPubkeyKeyPair)
	}

	if len(o.EcdhPubkey) > 0 {
		outputEcdhPubkeyKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
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
			KeyType: PsetProprietary,
			KeyData: proprietaryKey(OutputBlinderIndex, nil),
		},
		Value: outputBlinderIndexBytes,
	}
	keyPairs = append(keyPairs, outputBlinderIndexKeyPair)

	if len(o.BlindValueProof) > 0 {
		outputBlindValueProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(OutputBlindValueProof, nil),
			},
			Value: o.BlindValueProof,
		}
		keyPairs = append(keyPairs, outputBlindValueProofKeyPair)
	}

	if len(o.BlindAssetProof) > 0 {
		outputBlindAssetProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(OutputBlindAssetProof, nil),
			},
			Value: o.BlindAssetProof,
		}
		keyPairs = append(keyPairs, outputBlindAssetProofKeyPair)
	}

	for _, v := range o.ProprietaryData {
		kp := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
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
			if len(o.RedeemScript) > 0 {
				return ErrDuplicateKey
			}
			o.RedeemScript = kp.Value
		case OutputWitnessScript:
			if len(o.WitnessScript) > 0 {
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
			if len(o.Script) > 0 {
				return ErrDuplicateKey
			}
			o.Script = kp.Value
		case PsetProprietary:
			pd := ProprietaryData{}
			if err := pd.fromKeyPair(kp); err != nil {
				return err
			}

			if bytes.Equal(pd.Identifier, magicPrefix) {
				switch pd.Subtype {
				case OutputValueCommitment:
					if len(o.ValueCommitment) > 0 {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 33 {
						return ErrOutInvalidValueCommitment
					}
					o.ValueCommitment = kp.Value
				case OutputAsset:
					if len(o.Asset) > 0 {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 32 {
						return ErrOutInvalidAsset
					}
					o.Asset = kp.Value
				case OutputAssetCommitment:
					if len(o.AssetCommitment) > 0 {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 33 {
						return ErrOutInvalidAssetCommitment
					}
					o.AssetCommitment = kp.Value
				case OutputValueRangeproof:
					if len(o.ValueRangeproof) > 0 {
						return ErrDuplicateKey
					}
					o.ValueRangeproof = kp.Value
				case OutputAssetSurjectionProof:
					if len(o.AssetSurjectionProof) > 0 {
						return ErrDuplicateKey
					}
					o.AssetSurjectionProof = kp.Value
				case OutputBlindingPubkey:
					if len(o.BlindingPubkey) > 0 {
						return ErrDuplicateKey
					}
					if !validatePubkey(kp.Value) {
						return ErrOutInvalidBlindingPubKey
					}
					o.BlindingPubkey = kp.Value
				case OutputEcdhPubkey:
					if len(o.EcdhPubkey) > 0 {
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
					if len(o.BlindValueProof) > 0 {
						return ErrDuplicateKey
					}
					o.BlindValueProof = kp.Value
				case OutputBlindAssetProof:
					if len(o.BlindAssetProof) > 0 {
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
