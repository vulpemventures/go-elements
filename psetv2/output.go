package psetv2

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

const (
	//Per output types: BIP 174, 370, 371
	PsbtOutRedeemScript       = 0x00 //BIP 174
	PsbtOutWitnessScript      = 0x01 //BIP 174
	PsbtOutBip32Derivation    = 0x02 //BIP 174
	PsbtOutAmount             = 0x03 //BIP 370
	PsbtOutScript             = 0x04 //BIP 370
	PsbtOutTapInternalKey     = 0x05 //BIP 371
	PsbtOutTapTree            = 0x06 //BIP 371
	PsbtOutTapLeafScript      = 0x06 //BIP 371 //TODO is duplicate key type allowed?
	PsbtOutTapBip32Derivation = 0x07 //BIP 371
	PsbtOutProprietary        = 0xFC //BIP 174

	//Elements Proprietary types
	PsetElementsOutValueCommitment      = 0x01
	PsetElementsOutAsset                = 0x02
	PsetElementsOutAssetCommitment      = 0x03
	PsetElementsOutValueRangeproof      = 0x04
	PsetElementsOutAssetSurjectionProof = 0x05
	PsetElementsOutBlindingPubkey       = 0x06
	PsetElementsOutEcdhPubkey           = 0x07
	PsetElementsOutBlinderIndex         = 0x08
	PsetElementsOutBlindValueProof      = 0x09
	PsetElementsOutBlindAssetProof      = 0x0a
)

var (
	ErrMissingOutAsset                 = errors.New("missing output asset")
	ErrMissingOutAmount                = errors.New("missing output amount")
	ErrMissingScript                   = errors.New("missing output script")
	ErrInvalidValueCommitmentLength    = errors.New("invalid value commitment length")
	ErrInvalidOutAssetLength           = errors.New("invalid output asset length")
	ErrInvalidOutAssetCommitmentLength = errors.New("invalid output asset commitment length")
	ErrInvalidOutputScriptLength       = errors.New("invalid output script length")
)

type Output struct {
	// The redeem script for this output.
	redeemScript []byte
	// The witness script for this output.
	witnessScript []byte
	// A map from public keys needed to spend this output to their
	// corresponding master key fingerprints and derivation paths.
	bip32Derivation []DerivationPathWithPubKey
	// (PSET2) The amount of the output
	outputAmount *int64
	// (PSET2) The output script
	outputScript []byte
	// The 33 byte Value Commitment for this output.
	outputValueCommitment []byte
	// The explicit 32 byte asset tag for this output.
	outputAsset []byte
	// The 33 byte Asset Commitment
	outputAssetCommitment []byte
	// The rangeproof for the value of this output.
	outputValueRangeproof []byte
	// The asset surjection proof for this output's asset.
	outputAssetSurjectionProof []byte
	// The 33 byte blinding pubkey to be used when blinding this output.
	outputBlindingPubkey []byte
	// The 33 byte ephemeral pubkey used for ECDH in the blinding of this output
	outputEcdhPubkey []byte
	// Index of the input whose owner should blind this output.
	outputBlinderIndex *uint32
	// An explicit value rangeproof that proves that the value commitment in
	//PSBT_ELEMENTS_OUT_VALUE_COMMITMENT matches the explicit value in PSBT_OUT_VALUE
	outputBlindValueProof []byte
	// An asset surjection proof with this output's asset as the only asset in
	//the input set in order to prove that the asset commitment in
	//PSBT_ELEMENTS_OUT_ASSET_COMMITMENT matches the explicit asset in PSBT_ELEMENTS_OUT_ASSET
	outputBlindAssetProof []byte
	proprietaryData       []proprietaryData
	// Unknown key-value pairs for this input.
	unknowns []keyPair
}

func (o *Output) serialize() ([]byte, error) {
	s, err := bufferutil.NewSerializer(nil)
	if err != nil {
		return nil, err
	}

	outputKeyPairs, err := o.getKeyPairs()
	if err != nil {
		return nil, err
	}

	for _, v := range outputKeyPairs {
		kpBytes, err := serializeKeyPair(v)
		if err != nil {
			return nil, err
		}
		if err := s.WriteSlice(kpBytes); err != nil {
			return nil, err
		}
	}

	if err := s.WriteUint8(separator); err != nil {
		return nil, err
	}

	return s.Bytes(), nil
}

func (o *Output) getKeyPairs() ([]keyPair, error) {
	keyPairs := make([]keyPair, 0)

	if o.redeemScript != nil {
		redeemScriptKeyPair := keyPair{
			key: key{
				keyType: PsbtOutRedeemScript,
				keyData: nil,
			},
			value: o.redeemScript,
		}
		keyPairs = append(keyPairs, redeemScriptKeyPair)
	}

	if o.witnessScript != nil {
		witnessScriptKeyPair := keyPair{
			key: key{
				keyType: PsbtOutWitnessScript,
				keyData: nil,
			},
			value: o.witnessScript,
		}
		keyPairs = append(keyPairs, witnessScriptKeyPair)
	}

	if o.bip32Derivation != nil {
		for _, v := range o.bip32Derivation {
			bip32DerivationPathKeyPair := keyPair{
				key: key{
					keyType: PsbtOutBip32Derivation,
					keyData: v.PubKey,
				},
				value: SerializeBIP32Derivation(v.MasterKeyFingerprint, v.Bip32Path),
			}
			keyPairs = append(keyPairs, bip32DerivationPathKeyPair)
		}
	}

	if o.outputAmount != nil {
		outputAmountBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(outputAmountBytes, uint64(*o.outputAmount))
		outputAmountKeyPair := keyPair{
			key: key{
				keyType: PsbtOutAmount,
				keyData: nil,
			},
			value: outputAmountBytes,
		}
		keyPairs = append(keyPairs, outputAmountKeyPair)
	}

	if o.outputValueCommitment != nil {
		outputValueCommitmentKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutValueCommitment, nil),
			},
			value: o.outputValueCommitment,
		}
		keyPairs = append(keyPairs, outputValueCommitmentKeyPair)
	}

	if o.outputAsset != nil {
		outputAssetKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutAsset, nil),
			},
			value: o.outputAsset,
		}
		keyPairs = append(keyPairs, outputAssetKeyPair)
	}

	if o.outputAssetCommitment != nil {
		outputAssetCommitmentKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutAssetCommitment, nil),
			},
			value: o.outputAssetCommitment,
		}
		keyPairs = append(keyPairs, outputAssetCommitmentKeyPair)
	}

	if o.outputScript != nil {
		outputScriptKeyPair := keyPair{
			key: key{
				keyType: PsbtOutScript,
				keyData: nil,
			},
			value: o.outputScript,
		}
		keyPairs = append(keyPairs, outputScriptKeyPair)
	}

	if o.outputValueRangeproof != nil {
		outputValueRangeproofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutValueRangeproof, nil),
			},
			value: o.outputValueRangeproof,
		}
		keyPairs = append(keyPairs, outputValueRangeproofKeyPair)
	}

	if o.outputAssetSurjectionProof != nil {
		outputAssetSurjectionProofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutAssetSurjectionProof, nil),
			},
			value: o.outputAssetSurjectionProof,
		}
		keyPairs = append(keyPairs, outputAssetSurjectionProofKeyPair)
	}

	if o.outputBlindingPubkey != nil {
		outputBlindingPubkeyKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutBlindingPubkey, nil),
			},
			value: o.outputBlindingPubkey,
		}
		keyPairs = append(keyPairs, outputBlindingPubkeyKeyPair)
	}

	if o.outputEcdhPubkey != nil {
		outputEcdhPubkeyKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutEcdhPubkey, nil),
			},
			value: o.outputEcdhPubkey,
		}
		keyPairs = append(keyPairs, outputEcdhPubkeyKeyPair)
	}

	if o.outputBlinderIndex != nil {
		outputBlinderIndexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(outputBlinderIndexBytes, *o.outputBlinderIndex)

		outputBlinderIndexKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutBlinderIndex, nil),
			},
			value: outputBlinderIndexBytes,
		}
		keyPairs = append(keyPairs, outputBlinderIndexKeyPair)
	}

	if o.outputBlindValueProof != nil {
		outputBlindValueProofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutBlindValueProof, nil),
			},
			value: o.outputBlindValueProof,
		}
		keyPairs = append(keyPairs, outputBlindValueProofKeyPair)
	}

	for _, v := range o.proprietaryData {
		kp := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(v.subtype, v.keyData),
			},
			value: v.value,
		}
		keyPairs = append(keyPairs, kp)
	}

	for _, v := range o.unknowns {
		keyPairs = append(keyPairs, v)
	}

	return keyPairs, nil
}

func deserializeOutput(buf *bytes.Buffer) (*Output, error) {
	output := &Output{}

	kp := &keyPair{}

	outputAssetFound := false
	outputAmountFound := false
	outputScriptFound := false

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
		case PsbtOutRedeemScript:
			output.redeemScript = kp.value
		case PsbtOutWitnessScript:
			output.witnessScript = kp.value
		case PsbtOutBip32Derivation:
			if !validatePubkey(kp.key.keyData) {
				return nil, ErrInvalidPsbtFormat
			}
			master, derivationPath, err := readBip32Derivation(kp.value)
			if err != nil {
				return nil, err
			}

			// Duplicate keys are not allowed
			for _, x := range output.bip32Derivation {
				if bytes.Equal(x.PubKey, kp.key.keyData) {
					return nil, ErrDuplicatePubKeyInBip32DerPath
				}
			}

			output.bip32Derivation = append(
				output.bip32Derivation,
				DerivationPathWithPubKey{
					PubKey:               kp.key.keyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)
		case PsbtOutAmount:
			outputAmount := int64(binary.LittleEndian.Uint64(kp.value))
			output.outputAmount = &outputAmount
			outputAmountFound = true
		case PsbtOutScript:
			//TODO check if bellow validation is needed
			//if len(kp.value) == 0 {
			//	return nil, ErrInvalidOutputScriptLength
			//}
			output.outputScript = kp.value
			outputScriptFound = true
		case PsbtGlobalProprietary:
			pd := &proprietaryData{}
			if err := pd.proprietaryDataFromKeyPair(*kp); err != nil {
				return nil, err
			}

			if bytes.Equal(pd.identifier, psetMagic[:len(psetMagic)-1]) {
				switch pd.subtype {
				case PsetElementsOutValueCommitment:
					outValueCommitment := kp.value
					if len(outValueCommitment) != 33 {
						return nil, ErrInvalidValueCommitmentLength
					}

					outputAmountFound = true
					output.outputValueCommitment = outValueCommitment
				case PsetElementsOutAsset:
					outputAsset := kp.value
					if len(outputAsset) != 32 {
						return nil, ErrInvalidOutAssetLength
					}
					output.outputAsset = outputAsset
					outputAssetFound = true
				case PsetElementsOutAssetCommitment:
					outputAssetCommitment := kp.value
					if len(outputAssetCommitment) != 33 {
						return nil, ErrInvalidOutAssetCommitmentLength
					}
					outputAssetFound = true

					output.outputAssetCommitment = outputAssetCommitment
				case PsetElementsOutValueRangeproof:
					output.outputValueRangeproof = kp.value
				case PsetElementsOutAssetSurjectionProof:
					output.outputAssetSurjectionProof = kp.value
				case PsetElementsOutBlindingPubkey:
					if !validatePubkey(kp.value) {
						return nil, ErrInvalidPsbtFormat
					}

					output.outputBlindingPubkey = kp.value
				case PsetElementsOutEcdhPubkey:
					if !validatePubkey(kp.value) {
						return nil, ErrInvalidPsbtFormat
					}

					output.outputEcdhPubkey = kp.value
				case PsetElementsOutBlinderIndex:
					outputBlinderIndex := binary.LittleEndian.Uint32(kp.value)
					output.outputBlinderIndex = &outputBlinderIndex
				case PsetElementsOutBlindValueProof:
					output.outputBlindValueProof = kp.value
				case PsetElementsOutBlindAssetProof:
					output.outputBlindAssetProof = kp.value
				default:
					output.proprietaryData = append(output.proprietaryData, *pd)
				}
			}
		default:
			unknowns, err := deserializeUnknownKeyPairs(buf)
			if err != nil {
				return nil, err
			}
			output.unknowns = unknowns
		}
	}

	//validate mandatory fields
	if !outputAssetFound {
		return nil, ErrMissingOutAsset
	}

	if !outputAmountFound {
		return nil, ErrMissingOutAmount
	}

	if !outputScriptFound {
		return nil, ErrMissingScript
	}

	return output, nil
}
