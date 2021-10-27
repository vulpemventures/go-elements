package psetv2

import (
	"bytes"
	"encoding/binary"
)

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
