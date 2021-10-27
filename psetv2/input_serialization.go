package psetv2

import (
	"encoding/binary"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

func (i Input) serialize(s *bufferutil.Serializer) error {
	inputKeyPairs, err := i.getKeyPairs()
	if err != nil {
		return err
	}

	for _, v := range inputKeyPairs {
		if err := serializeKeyPair(v, s); err != nil {
			return err
		}
	}

	if err := s.WriteUint8(separator); err != nil {
		return err
	}

	return nil
}

func (i *Input) getKeyPairs() ([]keyPair, error) {
	keyPairs := make([]keyPair, 0)

	if i.nonWitnessUtxo != nil {
		nonWitnessUtxoBytes, err := i.nonWitnessUtxo.Serialize()
		if err != nil {
			return nil, err
		}
		nonWitnessKeyPair := keyPair{
			key: key{
				keyType: PsbtInNonWitnessUtxo,
				keyData: nil,
			},
			value: nonWitnessUtxoBytes,
		}
		keyPairs = append(keyPairs, nonWitnessKeyPair)
	}

	if i.witnessUtxo != nil {
		witnessUtxoBytes, err := writeTxOut(i.witnessUtxo)
		if err != nil {
			return nil, err
		}
		nonWitnessKeyPair := keyPair{
			key: key{
				keyType: PsbtInWitnessUtxo,
				keyData: nil,
			},
			value: witnessUtxoBytes,
		}
		keyPairs = append(keyPairs, nonWitnessKeyPair)
	}

	if i.partialSigs != nil {
		for _, v := range i.partialSigs {
			partialSigKeyPair := keyPair{
				key: key{
					keyType: PsbtInPartialSig,
					keyData: v.PubKey,
				},
				value: v.Signature,
			}
			keyPairs = append(keyPairs, partialSigKeyPair)
		}
	}

	if i.sigHashType != nil {
		sigHashTypeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sigHashTypeBytes, uint32(*i.sigHashType))
		fallBackLockTimeKeyPair := keyPair{
			key: key{
				keyType: PsbtInSighashType,
				keyData: nil,
			},
			value: sigHashTypeBytes,
		}
		keyPairs = append(keyPairs, fallBackLockTimeKeyPair)
	}

	if i.redeemScript != nil {
		redeemScriptKeyPair := keyPair{
			key: key{
				keyType: PsbtInRedeemScript,
				keyData: nil,
			},
			value: i.redeemScript,
		}
		keyPairs = append(keyPairs, redeemScriptKeyPair)
	}

	if i.witnessScript != nil {
		witnessScriptKeyPair := keyPair{
			key: key{
				keyType: PsbtInWitnessScript,
				keyData: nil,
			},
			value: i.witnessScript,
		}
		keyPairs = append(keyPairs, witnessScriptKeyPair)
	}

	if i.bip32Derivation != nil {
		for _, v := range i.bip32Derivation {
			bip32DerivationPathKeyPair := keyPair{
				key: key{
					keyType: PsbtInBip32Derivation,
					keyData: v.PubKey,
				},
				value: SerializeBIP32Derivation(v.MasterKeyFingerprint, v.Bip32Path),
			}
			keyPairs = append(keyPairs, bip32DerivationPathKeyPair)
		}
	}

	if i.finalScriptSig != nil {
		finalScriptSigKeyPair := keyPair{
			key: key{
				keyType: PsbtInFinalScriptsig,
				keyData: nil,
			},
			value: i.finalScriptSig,
		}
		keyPairs = append(keyPairs, finalScriptSigKeyPair)
	}

	if i.finalScriptWitness != nil {
		finalScriptWitnessKeyPair := keyPair{
			key: key{
				keyType: PsbtInFinalScriptwitness,
				keyData: nil,
			},
			value: i.finalScriptWitness,
		}
		keyPairs = append(keyPairs, finalScriptWitnessKeyPair)
	}

	if i.ripemd160Preimages != nil {
		for k, v := range i.ripemd160Preimages {
			ripemd160PreimagesKeyPair := keyPair{
				key: key{
					keyType: PsbtInRipemd160,
					keyData: k[:],
				},
				value: v,
			}
			keyPairs = append(keyPairs, ripemd160PreimagesKeyPair)
		}
	}

	if i.sha256Preimages != nil {
		for k, v := range i.sha256Preimages {
			sha256PreimagesKeyPair := keyPair{
				key: key{
					keyType: PsbtInSha256,
					keyData: k[:],
				},
				value: v,
			}
			keyPairs = append(keyPairs, sha256PreimagesKeyPair)
		}
	}

	if i.hash160Preimages != nil {
		for k, v := range i.hash160Preimages {
			hash160PreimagesKeyPair := keyPair{
				key: key{
					keyType: PsbtInHash160,
					keyData: k[:],
				},
				value: v,
			}
			keyPairs = append(keyPairs, hash160PreimagesKeyPair)
		}
	}

	if i.hash256Preimages != nil {
		for k, v := range i.hash256Preimages {
			hash256PreimagesKeyPair := keyPair{
				key: key{
					keyType: PsbtInHash256,
					keyData: k[:],
				},
				value: v,
			}
			keyPairs = append(keyPairs, hash256PreimagesKeyPair)
		}
	}

	if i.previousTxid != nil {
		previousTxidKeyPair := keyPair{
			key: key{
				keyType: PsbtInPreviousTxid,
				keyData: nil,
			},
			value: i.previousTxid,
		}
		keyPairs = append(keyPairs, previousTxidKeyPair)
	}

	if i.previousOutputIndex != nil {
		previousOutputIndexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(previousOutputIndexBytes, *i.previousOutputIndex)
		previousOutputIndexKeyPair := keyPair{
			key: key{
				keyType: PsbtInOutputIndex,
				keyData: nil,
			},
			value: previousOutputIndexBytes,
		}
		keyPairs = append(keyPairs, previousOutputIndexKeyPair)
	}

	if i.sequence != nil {
		sequenceBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequenceBytes, *i.sequence)
		sequenceKeyPair := keyPair{
			key: key{
				keyType: PsbtInSequence,
				keyData: nil,
			},
			value: sequenceBytes,
		}
		keyPairs = append(keyPairs, sequenceKeyPair)
	}

	if i.requiredTimeLocktime != nil {
		requiredTimeLocktimeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(requiredTimeLocktimeBytes, *i.requiredTimeLocktime)
		requiredTimeLocktimeKeyPair := keyPair{
			key: key{
				keyType: PsbtInRequiredTimeLocktime,
				keyData: nil,
			},
			value: requiredTimeLocktimeBytes,
		}
		keyPairs = append(keyPairs, requiredTimeLocktimeKeyPair)
	}

	if i.requiredHeightLocktime != nil {
		requiredHeightLocktimeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(requiredHeightLocktimeBytes, *i.requiredHeightLocktime)
		requiredHeightLocktimeKeyPair := keyPair{
			key: key{
				keyType: PsbtInRequiredTimeLocktime,
				keyData: nil,
			},
			value: requiredHeightLocktimeBytes,
		}
		keyPairs = append(keyPairs, requiredHeightLocktimeKeyPair)
	}

	if i.issuanceValue != nil {
		issuanceValueBytes := make([]byte, 4)
		binary.LittleEndian.PutUint64(issuanceValueBytes, uint64(*i.issuanceValue))
		issuanceValueKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceValue, nil),
			},
			value: issuanceValueBytes,
		}
		keyPairs = append(keyPairs, issuanceValueKeyPair)
	}

	if i.issuanceValueCommitment != nil {
		issuanceValueCommitmentKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceValueCommitment, nil),
			},
			value: i.issuanceValueCommitment,
		}
		keyPairs = append(keyPairs, issuanceValueCommitmentKeyPair)
	}

	if i.issuanceValueRangeproof != nil {
		issuanceValueRangeproofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceValueRangeproof, nil),
			},
			value: i.issuanceValueRangeproof,
		}
		keyPairs = append(keyPairs, issuanceValueRangeproofKeyPair)
	}

	if i.issuanceKeysRangeproof != nil {
		issuanceKeysRangeproofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceKeysRangeproof, nil),
			},
			value: i.issuanceKeysRangeproof,
		}
		keyPairs = append(keyPairs, issuanceKeysRangeproofKeyPair)
	}

	if i.peginTx != nil {
		peginTxBytes, err := i.peginTx.Serialize()
		if err != nil {
			return nil, err
		}

		peginTxKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInPegInTx, nil),
			},
			value: peginTxBytes,
		}
		keyPairs = append(keyPairs, peginTxKeyPair)
	}

	if i.peginTxoutProof != nil {
		peginTxoutProofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInPegInTxoutProof, nil),
			},
			value: i.peginTxoutProof,
		}
		keyPairs = append(keyPairs, peginTxoutProofKeyPair)
	}

	if i.peginGenesisHash != nil {
		peginGenesisHashKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInPegInGenesis, nil),
			},
			value: i.peginGenesisHash,
		}
		keyPairs = append(keyPairs, peginGenesisHashKeyPair)
	}

	if i.peginClaimScript != nil {
		peginClaimScriptKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInPegInClaimScript, nil),
			},
			value: i.peginClaimScript,
		}
		keyPairs = append(keyPairs, peginClaimScriptKeyPair)
	}

	if i.peginValue != nil {
		var peginValueBytes []byte
		binary.LittleEndian.PutUint64(peginValueBytes, uint64(*i.peginValue))

		peginValueKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInPegInValue, nil),
			},
			value: peginValueBytes,
		}
		keyPairs = append(keyPairs, peginValueKeyPair)
	}

	if i.peginWitness != nil {
		peginWitnessKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInPegInWitness, nil),
			},
			value: i.peginWitness,
		}
		keyPairs = append(keyPairs, peginWitnessKeyPair)
	}

	if i.issuanceInflationKeys != nil {
		var issuanceInflationKeysBytes []byte
		binary.LittleEndian.PutUint64(issuanceInflationKeysBytes, uint64(*i.issuanceInflationKeys))

		issuanceInflationKeysKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceInflationKeys, nil),
			},
			value: issuanceInflationKeysBytes,
		}
		keyPairs = append(keyPairs, issuanceInflationKeysKeyPair)
	}

	if i.issuanceInflationKeysCommitment != nil {
		issuanceInflationKeysCommitmentKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceInflationKeysCommitment, nil),
			},
			value: i.issuanceInflationKeysCommitment,
		}
		keyPairs = append(keyPairs, issuanceInflationKeysCommitmentKeyPair)
	}

	if i.issuanceBlindingNonce != nil {
		issuanceBlindingNonceKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceBlindingNonce, nil),
			},
			value: i.issuanceBlindingNonce,
		}
		keyPairs = append(keyPairs, issuanceBlindingNonceKeyPair)
	}

	if i.issuanceAssetEntropy != nil {
		issuanceAssetEntropyKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceAssetEntropy, nil),
			},
			value: i.issuanceAssetEntropy,
		}
		keyPairs = append(keyPairs, issuanceAssetEntropyKeyPair)
	}

	if i.inUtxoRangeProof != nil {
		inUtxoRangeProofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInUtxoRangeProof, nil),
			},
			value: i.inUtxoRangeProof,
		}
		keyPairs = append(keyPairs, inUtxoRangeProofKeyPair)
	}

	if i.issuanceBlindValueProof != nil {
		issuanceBlindValueProofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceBlindValueProof, nil),
			},
			value: i.issuanceBlindValueProof,
		}
		keyPairs = append(keyPairs, issuanceBlindValueProofKeyPair)
	}

	if i.issuanceBlindInflationKeysProof != nil {
		issuanceBlindInflationKeysProofKeyPair := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(PsetElementsInIssuanceBlindInflationKeysProof, nil),
			},
			value: i.issuanceBlindInflationKeysProof,
		}
		keyPairs = append(keyPairs, issuanceBlindInflationKeysProofKeyPair)
	}

	for _, v := range i.proprietaryData {
		kp := keyPair{
			key: key{
				keyType: PsbtGlobalProprietary,
				keyData: proprietaryKey(v.subtype, v.keyData),
			},
			value: v.value,
		}
		keyPairs = append(keyPairs, kp)
	}

	for _, v := range i.unknowns {
		keyPairs = append(keyPairs, v)
	}

	return keyPairs, nil
}
