package psetv2

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"

	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/transaction"
)

var (
	// ErrInvalidPsbtFormat is a generic error for any situation in which a
	// provided Psbt serialization does not conform to the rules of BIP174.
	ErrDuplicatePubKeyInPartSig      = errors.New("duplicate pubkey in partial signature")
	ErrDuplicatePubKeyInBip32DerPath = errors.New("duplicate pubkey in bip32 der path")
	// ErrInvalidKeydata indicates that a key-value pair in the PSBT
	// serialization contains data in the key which is not valid.
	ErrInvalidKeydata                               = errors.New("invalid key data")
	ErrMissingPrevTxID                              = errors.New("missing previous tx id")
	ErrMissingOutputIndex                           = errors.New("missing output index")
	ErrInvalidPrevTxIdLength                        = errors.New("invalid previous tx id length")
	ErrInvalidIssuanceValueCommitmentLength         = errors.New("invalid issuance value commitment length")
	ErrInvalidPeginGenesisHashLength                = errors.New("invalid pegin genesis hash length")
	ErrInvalidIssuanceInflationKeysCommitmentLength = errors.New("invalid issuance inflation keys commitment")
	ErrInvalidIssuanceBlindingNonceLength           = errors.New("invalid issuance blinding nonce length")
	ErrInvalidIssuanceAssetEntropyLength            = errors.New("invalid issuance asset entropy length")
)

const (
	//Per input types: BIP 127, 174, 370, 371
	PsbtInNonWitnessUtxo         = 0x00 //BIP 174
	PsbtInWitnessUtxo            = 0x01 //BIP 174
	PsbtInPartialSig             = 0x02 //BIP 174
	PsbtInSighashType            = 0x03 //BIP 174
	PsbtInRedeemScript           = 0x04 //BIP 174
	PsbtInWitnessScript          = 0x05 //BIP 174
	PsbtInBip32Derivation        = 0x06 //BIP 174
	PsbtInFinalScriptsig         = 0x07 //BIP 174
	PsbtInFinalScriptwitness     = 0x08 //BIP 174
	PsbtInPorCommitment          = 0x09 //BIP 127
	PsbtInRipemd160              = 0x0a //BIP 174
	PsbtInSha256                 = 0x0b //BIP 174
	PsbtInHash160                = 0x0c //BIP 174
	PsbtInHash256                = 0x0d //BIP 174
	PsbtInPreviousTxid           = 0x0e //BIP 370
	PsbtInOutputIndex            = 0x0f //BIP 370
	PsbtInSequence               = 0x10 //BIP 370
	PsbtInRequiredTimeLocktime   = 0x11 //BIP 370
	PsbtInRequiredHeightLocktime = 0x12 //BIP 370
	PsbtInTapKeySig              = 0x13 //BIP 371
	PsbtInTapScriptSig           = 0x14 //BIP 371
	PsbtInTapLeafScript          = 0x15 //BIP 371
	PsbtInTapBip32Derivation     = 0x16 //BIP 371
	PsbtInTapInternalKey         = 0x17 //BIP 371
	PsbtInTapMerkleRoot          = 0x18 //BIP 371
	PsbtInProprietary            = 0xFC //BIP 174

	//Elements Proprietary types
	PsetElementsInIssuanceValue                   = 0x00
	PsetElementsInIssuanceValueCommitment         = 0x01
	PsetElementsInIssuanceValueRangeproof         = 0x02
	PsetElementsInIssuanceKeysRangeproof          = 0x03
	PsetElementsInPegInTx                         = 0x04
	PsetElementsInPegInTxoutProof                 = 0x05
	PsetElementsInPegInGenesis                    = 0x06
	PsetElementsInPegInClaimScript                = 0x07
	PsetElementsInPegInValue                      = 0x08
	PsetElementsInPegInWitness                    = 0x09
	PsetElementsInIssuanceInflationKeys           = 0x0a
	PsetElementsInIssuanceInflationKeysCommitment = 0x0b
	PsetElementsInIssuanceBlindingNonce           = 0x0c
	PsetElementsInIssuanceAssetEntropy            = 0x0d
	PsetElementsInUtxoRangeProof                  = 0x0e
	PsetElementsInIssuanceBlindValueProof         = 0x0f
	PsetElementsInIssuanceBlindInflationKeysProof = 0x10
)

type Input struct {
	// The non-witness transaction this input spends from. Should only be
	// [std::option::Option::Some] for inputs which spend non-segwit outputs or
	// if it is unknowns whether an input spends a segwit output.
	nonWitnessUtxo *transaction.Transaction
	// The transaction output this input spends from. Should only be
	// [std::option::Option::Some] for inputs which spend segwit outputs,
	// including P2SH embedded ones.
	witnessUtxo *transaction.TxOutput
	// A map from public keys to their corresponding signature as would be
	// pushed to the stack from a scriptSig or witness.
	partialSigs []PartialSig
	// The sighash type to be used for this input. Signatures for this input
	// must use the sighash type.
	sigHashType *txscript.SigHashType
	// The redeem script for this input.
	redeemScript []byte
	/// The witness script for this input.
	witnessScript []byte
	// A map from public keys needed to sign this input to their corresponding
	// master key fingerprints and derivation paths.
	bip32Derivation []DerivationPathWithPubKey
	// The finalized, fully-constructed scriptSig with signatures and any other
	// scripts necessary for this input to pass validation.
	finalScriptSig []byte
	// The finalized, fully-constructed scriptWitness with signatures and any
	// other scripts necessary for this input to pass validation.
	finalScriptWitness []byte
	// RIPEMD160 hash to preimage map
	ripemd160Preimages map[[20]byte][]byte
	// SHA256 hash to preimage map
	sha256Preimages map[[32]byte][]byte
	// HSAH160 hash to preimage map
	hash160Preimages map[[20]byte][]byte
	// HAS256 hash to preimage map
	hash256Preimages map[[32]byte][]byte
	// (PSET2) Prevout TXID of the input
	previousTxid []byte
	// (PSET2) Prevout vout of the input
	previousOutputIndex *uint32
	// (PSET2) Sequence number. If omitted, defaults to 0xffffffff
	sequence *uint32
	// (PSET2) Minimum required locktime, as a UNIX timestamp. If present, must be greater than or equal to 500000000
	requiredTimeLocktime *uint32
	// (PSET2) Minimum required locktime, as a blockheight. If present, must be less than 500000000
	requiredHeightLocktime *uint32
	// Proprietary key-value pairs for this input.
	// The issuance value
	issuanceValue *int64
	// Issuance value commitment
	issuanceValueCommitment []byte
	// Issuance value rangeproof
	issuanceValueRangeproof []byte
	// Issuance keys rangeproof
	issuanceKeysRangeproof []byte
	// Pegin Transaction. Should be a bitcoin::Transaction
	peginTx *transaction.Transaction
	// Pegin Transaction proof
	// TODO: Look for Merkle proof structs
	peginTxoutProof []byte
	// Pegin genesis hash
	peginGenesisHash []byte
	// Claim script
	peginClaimScript []byte
	// Pegin Value
	peginValue *int64
	// Pegin Witness
	peginWitness []byte
	// Issuance inflation keys
	issuanceInflationKeys *int64
	// Issuance inflation keys commitment
	issuanceInflationKeysCommitment []byte
	// Issuance blinding nonce
	issuanceBlindingNonce []byte
	// Issuance asset entropy
	issuanceAssetEntropy []byte
	// Input utxo rangeproof
	inUtxoRangeProof []byte
	// IssuanceBlindValueProof
	issuanceBlindValueProof []byte
	// Issuance blind inflation keys proof
	issuanceBlindInflationKeysProof []byte
	// Other fields
	proprietaryData []proprietaryData
	// Unknown key-value pairs for this input.
	unknowns []keyPair
}

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

func readTxOut(txout []byte) (*transaction.TxOutput, error) {
	if len(txout) < 45 {
		return nil, ErrInvalidPsbtFormat
	}
	d := bufferutil.NewDeserializer(bytes.NewBuffer(txout))
	asset, err := d.ReadElementsAsset()
	if err != nil {
		return nil, err
	}
	value, err := d.ReadElementsValue()
	if err != nil {
		return nil, err
	}
	nonce, err := d.ReadElementsNonce()
	if err != nil {
		return nil, err
	}
	script, err := d.ReadVarSlice()
	if err != nil {
		return nil, err
	}
	surjectionProof := make([]byte, 0)
	rangeProof := make([]byte, 0)
	// nonce for unconf outputs is 0x00!
	if len(nonce) > 1 {
		surjectionProof, err = d.ReadVarSlice()
		if err != nil {
			return nil, err
		}
		rangeProof, err = d.ReadVarSlice()
		if err != nil {
			return nil, err
		}
	}
	return &transaction.TxOutput{
		Asset:           asset,
		Value:           value,
		Script:          script,
		Nonce:           nonce,
		RangeProof:      rangeProof,
		SurjectionProof: surjectionProof,
	}, nil
}
