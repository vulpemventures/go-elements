package psetv2

import (
	"encoding/binary"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

func (o *Output) serialize(s *bufferutil.Serializer) error {
	outputKeyPairs, err := o.getKeyPairs()
	if err != nil {
		return err
	}

	for _, v := range outputKeyPairs {
		if err := serializeKeyPair(v, s); err != nil {
			return err
		}
	}

	if err := s.WriteUint8(separator); err != nil {
		return err
	}

	return nil
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

	if o.outputBlindAssetProof != nil {
		outputBlindAssetProofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsOutBlindAssetProof, nil),
			},
			value: o.outputBlindAssetProof,
		}
		keyPairs = append(keyPairs, outputBlindAssetProofKeyPair)
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
