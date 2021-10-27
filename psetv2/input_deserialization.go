package psetv2

import (
	"bytes"
	"encoding/binary"

	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/transaction"
)

func deserializeInput(buf *bytes.Buffer) (*Input, error) {
	input := Input{
		partialSigs:     make([]PartialSig, 0),
		bip32Derivation: make([]DerivationPathWithPubKey, 0),
	}

	kp := &keyPair{}

	outputIndexFound := false
	prevTxIDFound := false

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
		case PsbtInNonWitnessUtxo:
			tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(kp.value))
			if err != nil {
				return nil, err
			}

			input.nonWitnessUtxo = tx
		case PsbtInWitnessUtxo:
			txOut, err := readTxOut(kp.value)
			if err != nil {
				return nil, err
			}

			input.witnessUtxo = txOut
		case PsbtInPartialSig:
			partialSignature := PartialSig{
				PubKey:    kp.key.keyData,
				Signature: kp.value,
			}

			if !partialSignature.checkValid() {
				return nil, ErrInvalidPsbtFormat
			}

			// Duplicate keys are not allowed
			for _, v := range input.partialSigs {
				if bytes.Equal(v.PubKey, partialSignature.PubKey) {
					return nil, ErrDuplicatePubKeyInPartSig
				}
			}

			input.partialSigs = append(input.partialSigs, partialSignature)
		case PsbtInSighashType:
			if len(kp.value) != 4 {
				return nil, ErrInvalidKeydata
			}

			sigHashType := txscript.SigHashType(
				binary.LittleEndian.Uint32(kp.value),
			)

			input.sigHashType = &sigHashType
		case PsbtInRedeemScript:
			input.redeemScript = kp.value
		case PsbtInWitnessScript:
			input.witnessScript = kp.value
		case PsbtInBip32Derivation:
			if !validatePubkey(kp.key.keyData) {
				return nil, ErrInvalidPsbtFormat
			}
			master, derivationPath, err := readBip32Derivation(kp.value)
			if err != nil {
				return nil, err
			}

			// Duplicate keys are not allowed
			for _, x := range input.bip32Derivation {
				if bytes.Equal(x.PubKey, kp.key.keyData) {
					return nil, ErrDuplicatePubKeyInBip32DerPath
				}
			}

			input.bip32Derivation = append(
				input.bip32Derivation,
				DerivationPathWithPubKey{
					PubKey:               kp.key.keyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)
		case PsbtInFinalScriptsig:
			input.finalScriptSig = kp.value
		case PsbtInFinalScriptwitness:
			input.finalScriptWitness = kp.value
		case PsbtInRipemd160:
			ripemd160Preimages := make(map[[20]byte][]byte)
			var hash [20]byte
			copy(hash[:], kp.key.keyData[:])
			ripemd160Preimages[hash] = kp.value
			input.ripemd160Preimages = ripemd160Preimages
		case PsbtInSha256:
			sha256Preimages := make(map[[32]byte][]byte)
			var hash [32]byte
			copy(hash[:], kp.key.keyData[:])
			sha256Preimages[hash] = kp.value
			input.sha256Preimages = sha256Preimages
		case PsbtInHash160:
			hash160Preimages := make(map[[20]byte][]byte)
			var hash [20]byte
			copy(hash[:], kp.key.keyData[:])
			hash160Preimages[hash] = kp.value
			input.hash160Preimages = hash160Preimages
		case PsbtInHash256:
			hash256Preimages := make(map[[32]byte][]byte)
			var hash [32]byte
			copy(hash[:], kp.key.keyData[:])
			input.hash256Preimages = hash256Preimages
		case PsbtInPreviousTxid:
			previousTxid := kp.value
			if len(previousTxid) != 32 {
				return nil, ErrInvalidPrevTxIdLength
			}

			input.previousTxid = previousTxid
			prevTxIDFound = true
		case PsbtInOutputIndex:
			prevOutIndex := binary.LittleEndian.Uint32(kp.value)
			input.previousOutputIndex = &prevOutIndex
			outputIndexFound = true
		case PsbtInSequence:
			sequence := binary.LittleEndian.Uint32(kp.value)
			input.sequence = &sequence
		case PsbtInRequiredTimeLocktime:
			requiredTimeLocktime := binary.LittleEndian.Uint32(kp.value)
			input.requiredTimeLocktime = &requiredTimeLocktime
		case PsbtInRequiredHeightLocktime:
			requiredHeightLocktime := binary.LittleEndian.Uint32(kp.value)
			input.requiredHeightLocktime = &requiredHeightLocktime
		case PsbtGlobalProprietary:
			pd := &proprietaryData{}
			if err := pd.proprietaryDataFromKeyPair(*kp); err != nil {
				return nil, err
			}

			if bytes.Equal(pd.identifier, psetMagic) {
				switch pd.subtype {
				case PsetElementsInIssuanceValue:
					issuanceValue := int64(binary.LittleEndian.Uint64(kp.value))
					input.issuanceValue = &issuanceValue
				case PsetElementsInIssuanceValueCommitment:
					issuanceValueCommitment := kp.value
					if len(issuanceValueCommitment) != 33 {
						return nil, ErrInvalidIssuanceValueCommitmentLength
					}

					input.issuanceValueCommitment = issuanceValueCommitment
				case PsetElementsInIssuanceValueRangeproof:
					input.issuanceValueRangeproof = kp.value
				case PsetElementsInIssuanceKeysRangeproof:
					input.issuanceKeysRangeproof = kp.value
				case PsetElementsInPegInTx:
					tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(kp.value))
					if err != nil {
						return nil, err
					}

					input.peginTx = tx
				case PsetElementsInPegInTxoutProof:
					input.peginTxoutProof = kp.value
				case PsetElementsInPegInGenesis:
					peginGenesisHash := kp.value[:]
					if len(peginGenesisHash) != 32 {
						return nil, ErrInvalidPeginGenesisHashLength
					}

					input.peginGenesisHash = peginGenesisHash
				case PsetElementsInPegInClaimScript:
					input.peginClaimScript = kp.value
				case PsetElementsInPegInValue:
					peginValue := int64(binary.LittleEndian.Uint64(kp.value))
					input.peginValue = &peginValue
				case PsetElementsInPegInWitness:
					input.peginWitness = kp.value
				case PsetElementsInIssuanceInflationKeys:
					issuanceInflationKeys := int64(binary.LittleEndian.Uint64(kp.value))
					input.issuanceInflationKeys = &issuanceInflationKeys
				case PsetElementsInIssuanceInflationKeysCommitment:
					issuanceInflationKeysCommitment := kp.value[:]
					if len(issuanceInflationKeysCommitment) != 33 {
						return nil, ErrInvalidIssuanceInflationKeysCommitmentLength
					}

					input.issuanceInflationKeysCommitment = issuanceInflationKeysCommitment
				case PsetElementsInIssuanceBlindingNonce:
					issuanceBlindingNonce := kp.value[:]
					if len(issuanceBlindingNonce) != 32 {
						return nil, ErrInvalidIssuanceBlindingNonceLength
					}

					input.issuanceBlindingNonce = issuanceBlindingNonce
				case PsetElementsInIssuanceAssetEntropy:
					issuanceAssetEntropy := kp.value[:]
					if len(issuanceAssetEntropy) != 32 {
						return nil, ErrInvalidIssuanceAssetEntropyLength
					}

					input.issuanceAssetEntropy = issuanceAssetEntropy
				case PsetElementsInUtxoRangeProof:
					input.inUtxoRangeProof = kp.value
				case PsetElementsInIssuanceBlindValueProof:
					input.issuanceBlindValueProof = kp.value
				case PsetElementsInIssuanceBlindInflationKeysProof:
					input.issuanceBlindInflationKeysProof = kp.value
				default:
					input.proprietaryData = append(input.proprietaryData, *pd)
				}
			}
		default:
			unknowns, err := deserializeUnknownKeyPairs(buf)
			if err != nil {
				return nil, err
			}
			input.unknowns = unknowns
		}
	}

	//validate mandatory fields
	if !prevTxIDFound {
		return nil, ErrMissingPrevTxID
	}

	if !outputIndexFound {
		return nil, ErrMissingOutputIndex
	}

	return &input, nil
}
