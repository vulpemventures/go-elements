package psetv2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	//Per input types: BIP 127, 174, 370, 371
	InputNonWitnessUtxo         = 0x00 //BIP 174
	InputWitnessUtxo            = 0x01 //BIP 174
	InputPartialSig             = 0x02 //BIP 174
	InputSighashType            = 0x03 //BIP 174
	InputRedeemScript           = 0x04 //BIP 174
	InputWitnessScript          = 0x05 //BIP 174
	InputBip32Derivation        = 0x06 //BIP 174
	InputFinalScriptsig         = 0x07 //BIP 174
	InputFinalScriptwitness     = 0x08 //BIP 174
	InputPorCommitment          = 0x09 //BIP 127
	InputRipemd160              = 0x0a //BIP 174
	InputSha256                 = 0x0b //BIP 174
	InputHash160                = 0x0c //BIP 174
	InputHash256                = 0x0d //BIP 174
	InputPreviousTxid           = 0x0e //BIP 370
	InputPreviousTxIndex        = 0x0f //BIP 370
	InputSequence               = 0x10 //BIP 370
	InputRequiredTimeLocktime   = 0x11 //BIP 370
	InputRequiredHeightLocktime = 0x12 //BIP 370
	InputTapKeySig              = 0x13 //BIP 371
	InputTapScriptSig           = 0x14 //BIP 371
	InputTapLeafScript          = 0x15 //BIP 371
	InputTapBip32Derivation     = 0x16 //BIP 371
	InputTapInternalKey         = 0x17 //BIP 371
	InputTapMerkleRoot          = 0x18 //BIP 371
	InputProprietary            = 0xFC //BIP 174

	//Elements Proprietary types
	InputIssuanceValue                   = 0x00
	InputIssuanceValueCommitment         = 0x01
	InputIssuanceValueRangeproof         = 0x02
	InputIssuanceInflationKeysRangeproof = 0x03
	InputPeginTx                         = 0x04
	InputPeginTxoutProof                 = 0x05
	InputPeginGenesis                    = 0x06
	InputPeginClaimScript                = 0x07
	InputPeginValue                      = 0x08
	InputPeginWitness                    = 0x09
	InputIssuanceInflationKeys           = 0x0a
	InputIssuanceInflationKeysCommitment = 0x0b
	InputIssuanceBlindingNonce           = 0x0c
	InputIssuanceAssetEntropy            = 0x0d
	InputUtxoRangeProof                  = 0x0e
	InputIssuanceBlindValueProof         = 0x0f
	InputIssuanceBlindInflationKeysProof = 0x10
)

var (
	ErrInInvalidPartialSignature = fmt.Errorf(
		"invalid input partial signature",
	)
	ErrInInvalidSigHash = fmt.Errorf(
		"invalid input sighash length",
	)
	ErrInInvalidPubKey = fmt.Errorf(
		"invalid input pubkey length",
	)
	ErrInInvalidPreviousTxid = fmt.Errorf(
		"invalid input prev txid length",
	)
	ErrInInvalidPreviousTxIndex = fmt.Errorf(
		"invalid input prev tx index length",
	)
	ErrInInvalidSequence = fmt.Errorf(
		"invalid input sequence length",
	)
	ErrInInvalidRequiredLocktime = fmt.Errorf(
		"invalid input required locktime length",
	)
	ErrInInvalidRequiredHeightLocktime = fmt.Errorf(
		"invalid input required height locktime length",
	)
	ErrInInvalidIssuanceValue = fmt.Errorf(
		"invalid input issuance value length",
	)
	ErrInInvalidIssuanceCommitment = fmt.Errorf(
		"invalid input issuance value commitment length",
	)
	ErrInInvalidPeginGenesisHash = fmt.Errorf(
		"invalid input pegin genesis hash length",
	)
	ErrInInvalidPeginValue = fmt.Errorf(
		"invalid input pegin value length",
	)
	ErrInInvalidIssuanceInflationKeys = fmt.Errorf(
		"invalid input issuance inflation keys length",
	)
	ErrInInvalidIssuanceInflationKeysCommitment = fmt.Errorf(
		"invalid input issuance inflation keys commitment length",
	)
	ErrInInvalidIssuanceBlindingNonce = fmt.Errorf(
		"invalid input issuance blinding nonce length",
	)
	ErrInInvalidIssuanceAssetEntropy = fmt.Errorf(
		"invalid input issuance asset entropy length",
	)
	ErrInInvalidWitnessScript = fmt.Errorf(
		"input witness script cannot be set if witness utxo is unset",
	)
	ErrInInvalidFinalScriptWitness = fmt.Errorf(
		"input final script witness cannot be set if witness utxo is unset",
	)
	ErrInInvalidIssuanceBlinding = fmt.Errorf(
		"input issuance value commitment and range proof must be both either " +
			"set or unset",
	)
	ErrInInvalidIssuanceInflationKeysBlinding = fmt.Errorf(
		"input issuance inflation keys commitment and range proof must be both " +
			"either set or unset",
	)
	ErrInInvalidLocktime       = fmt.Errorf("invalid input locktime")
	ErrInInvalidNonWitnessUtxo = fmt.Errorf(
		"non-witness utxo hash does not match input txid",
	)
)

type Input struct {
	NonWitnessUtxo                  *transaction.Transaction
	WitnessUtxo                     *transaction.TxOutput
	PartialSigs                     []PartialSig
	SigHashType                     txscript.SigHashType
	RedeemScript                    []byte
	WitnessScript                   []byte
	Bip32Derivation                 []DerivationPathWithPubKey
	FinalScriptSig                  []byte
	FinalScriptWitness              []byte
	Ripemd160Preimages              map[[20]byte][]byte
	Sha256Preimages                 map[[32]byte][]byte
	Hash160Preimages                map[[20]byte][]byte
	Hash256Preimages                map[[32]byte][]byte
	PreviousTxid                    []byte
	PreviousTxIndex                 uint32
	Sequence                        uint32
	RequiredTimeLocktime            uint32
	RequiredHeightLocktime          uint32
	IssuanceValue                   uint64
	IssuanceValueCommitment         []byte
	IssuanceValueRangeproof         []byte
	IssuanceInflationKeysRangeproof []byte
	PeginTx                         *transaction.Transaction
	PeginTxoutProof                 []byte
	PeginGenesisHash                []byte
	PeginClaimScript                []byte
	PeginValue                      uint64
	PeginWitness                    []byte
	IssuanceInflationKeys           uint64
	IssuanceInflationKeysCommitment []byte
	IssuanceBlindingNonce           []byte
	IssuanceAssetEntropy            []byte
	UtxoRangeProof                  []byte
	IssuanceBlindValueProof         []byte
	IssuanceBlindInflationKeysProof []byte
	ProprietaryData                 []ProprietaryData
	Unknowns                        []KeyPair
}

func (i *Input) SanityCheck() error {
	if i.WitnessUtxo == nil && len(i.WitnessScript) > 0 {
		return ErrInInvalidWitnessScript
	}
	if i.WitnessUtxo == nil && len(i.FinalScriptWitness) > 0 {
		return ErrInInvalidFinalScriptWitness
	}
	if len(i.PreviousTxid) == 0 {
		return ErrInMissingTxid
	}
	issuanceValueCommitmentSet := len(i.IssuanceValueCommitment) > 0
	issuanceValueRangeproofSet := len(i.IssuanceValueRangeproof) > 0
	if issuanceValueCommitmentSet != issuanceValueRangeproofSet {
		return ErrInInvalidIssuanceBlinding
	}
	issuanceInflationKeysCommitmentSet := len(i.IssuanceInflationKeysCommitment) > 0
	issuanceInflationKeysRangeproofSet := len(i.IssuanceInflationKeysRangeproof) > 0
	if issuanceInflationKeysCommitmentSet != issuanceInflationKeysRangeproofSet {
		return ErrInInvalidIssuanceInflationKeysBlinding
	}

	return nil
}

func (i *Input) HasIssuance() bool {
	return i.IssuanceValue > 0 || i.IssuanceInflationKeys > 0
}

func (i *Input) HasIssuanceBlinded() bool {
	return len(i.IssuanceValueCommitment) > 0
}

func (i *Input) HasReissuance() bool {
	if len(i.IssuanceBlindingNonce) > 0 {
		return false
	}
	return !bytes.Equal(i.IssuanceBlindingNonce, transaction.Zero[:])
}

func (i *Input) GetIssuanceAssetHash() []byte {
	if !i.HasIssuance() {
		return nil
	}

	issuance := transaction.NewTxIssuanceFromEntropy(i.IssuanceAssetEntropy)
	if !i.HasReissuance() {
		issuance = transaction.NewTxIssuanceFromContractHash(i.IssuanceAssetEntropy)
		issuance.GenerateEntropy(i.PreviousTxid, i.PreviousTxIndex)
	}

	assetHash, _ := issuance.GenerateAsset()
	return assetHash
}

func (i *Input) GetIssuanceInflationKeysHash(blindedIssuance bool) []byte {
	if !i.HasIssuance() {
		return nil
	}

	issuance := transaction.NewTxIssuanceFromEntropy(i.IssuanceAssetEntropy)
	if !i.HasReissuance() {
		issuance = transaction.NewTxIssuanceFromContractHash(i.IssuanceAssetEntropy)
		issuance.GenerateEntropy(i.PreviousTxid, i.PreviousTxIndex)
	}

	var flag uint
	if blindedIssuance {
		flag = 1
	}
	assetHash, _ := issuance.GenerateReissuanceToken(flag)
	return assetHash
}

func (i *Input) GetUtxo() *transaction.TxOutput {
	if i.WitnessUtxo != nil {
		return i.WitnessUtxo
	}
	if i.NonWitnessUtxo != nil {
		return i.NonWitnessUtxo.Outputs[i.PreviousTxIndex]
	}
	return nil
}

func (i *Input) getKeyPairs() ([]KeyPair, error) {
	keyPairs := make([]KeyPair, 0)

	if i.NonWitnessUtxo != nil {
		nonWitnessUtxoBytes, err := i.NonWitnessUtxo.Serialize()
		if err != nil {
			return nil, err
		}
		nonWitnessKeyPair := KeyPair{
			Key: Key{
				KeyType: InputNonWitnessUtxo,
				KeyData: nil,
			},
			Value: nonWitnessUtxoBytes,
		}
		keyPairs = append(keyPairs, nonWitnessKeyPair)
	}

	if i.WitnessUtxo != nil {
		witnessUtxoBytes, err := writeTxOut(i.WitnessUtxo)
		if err != nil {
			return nil, err
		}
		nonWitnessKeyPair := KeyPair{
			Key: Key{
				KeyType: InputWitnessUtxo,
				KeyData: nil,
			},
			Value: witnessUtxoBytes,
		}
		keyPairs = append(keyPairs, nonWitnessKeyPair)
	}

	if i.PartialSigs != nil {
		for _, v := range i.PartialSigs {
			partialSigKeyPair := KeyPair{
				Key: Key{
					KeyType: InputPartialSig,
					KeyData: v.PubKey,
				},
				Value: v.Signature,
			}
			keyPairs = append(keyPairs, partialSigKeyPair)
		}
	}

	if i.SigHashType != 0 {
		sigHashTypeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sigHashTypeBytes, uint32(i.SigHashType))
		fallBackLockTimeKeyPair := KeyPair{
			Key: Key{
				KeyType: InputSighashType,
				KeyData: nil,
			},
			Value: sigHashTypeBytes,
		}
		keyPairs = append(keyPairs, fallBackLockTimeKeyPair)
	}

	if i.RedeemScript != nil {
		redeemScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: InputRedeemScript,
				KeyData: nil,
			},
			Value: i.RedeemScript,
		}
		keyPairs = append(keyPairs, redeemScriptKeyPair)
	}

	if i.WitnessScript != nil {
		witnessScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: InputWitnessScript,
				KeyData: nil,
			},
			Value: i.WitnessScript,
		}
		keyPairs = append(keyPairs, witnessScriptKeyPair)
	}

	if i.Bip32Derivation != nil {
		for _, v := range i.Bip32Derivation {
			bip32DerivationPathKeyPair := KeyPair{
				Key: Key{
					KeyType: InputBip32Derivation,
					KeyData: v.PubKey,
				},
				Value: SerializeBIP32Derivation(v.MasterKeyFingerprint, v.Bip32Path),
			}
			keyPairs = append(keyPairs, bip32DerivationPathKeyPair)
		}
	}

	if i.FinalScriptSig != nil {
		finalScriptSigKeyPair := KeyPair{
			Key: Key{
				KeyType: InputFinalScriptsig,
				KeyData: nil,
			},
			Value: i.FinalScriptSig,
		}
		keyPairs = append(keyPairs, finalScriptSigKeyPair)
	}

	if i.FinalScriptWitness != nil {
		finalScriptWitnessKeyPair := KeyPair{
			Key: Key{
				KeyType: InputFinalScriptwitness,
				KeyData: nil,
			},
			Value: i.FinalScriptWitness,
		}
		keyPairs = append(keyPairs, finalScriptWitnessKeyPair)
	}

	if i.Ripemd160Preimages != nil {
		for k, v := range i.Ripemd160Preimages {
			ripemd160PreimagesKeyPair := KeyPair{
				Key: Key{
					KeyType: InputRipemd160,
					KeyData: k[:],
				},
				Value: v,
			}
			keyPairs = append(keyPairs, ripemd160PreimagesKeyPair)
		}
	}

	if i.Sha256Preimages != nil {
		for k, v := range i.Sha256Preimages {
			sha256PreimagesKeyPair := KeyPair{
				Key: Key{
					KeyType: InputSha256,
					KeyData: k[:],
				},
				Value: v,
			}
			keyPairs = append(keyPairs, sha256PreimagesKeyPair)
		}
	}

	if i.Hash160Preimages != nil {
		for k, v := range i.Hash160Preimages {
			hash160PreimagesKeyPair := KeyPair{
				Key: Key{
					KeyType: InputHash160,
					KeyData: k[:],
				},
				Value: v,
			}
			keyPairs = append(keyPairs, hash160PreimagesKeyPair)
		}
	}

	if i.Hash256Preimages != nil {
		for k, v := range i.Hash256Preimages {
			hash256PreimagesKeyPair := KeyPair{
				Key: Key{
					KeyType: InputHash256,
					KeyData: k[:],
				},
				Value: v,
			}
			keyPairs = append(keyPairs, hash256PreimagesKeyPair)
		}
	}

	previousTxidKeyPair := KeyPair{
		Key: Key{
			KeyType: InputPreviousTxid,
			KeyData: nil,
		},
		Value: i.PreviousTxid,
	}
	keyPairs = append(keyPairs, previousTxidKeyPair)

	prevTxIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(prevTxIndex, i.PreviousTxIndex)
	previousOutputIndexKeyPair := KeyPair{
		Key: Key{
			KeyType: InputPreviousTxIndex,
			KeyData: nil,
		},
		Value: prevTxIndex,
	}
	keyPairs = append(keyPairs, previousOutputIndexKeyPair)

	sequenceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sequenceBytes, i.Sequence)
	sequenceKeyPair := KeyPair{
		Key: Key{
			KeyType: InputSequence,
			KeyData: nil,
		},
		Value: sequenceBytes,
	}
	keyPairs = append(keyPairs, sequenceKeyPair)

	if i.RequiredTimeLocktime != 0 {
		requiredTimeLocktimeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(requiredTimeLocktimeBytes, i.RequiredTimeLocktime)
		requiredTimeLocktimeKeyPair := KeyPair{
			Key: Key{
				KeyType: InputRequiredTimeLocktime,
				KeyData: nil,
			},
			Value: requiredTimeLocktimeBytes,
		}
		keyPairs = append(keyPairs, requiredTimeLocktimeKeyPair)
	}

	if i.RequiredHeightLocktime != 0 {
		requiredHeightLocktimeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(requiredHeightLocktimeBytes, i.RequiredHeightLocktime)
		requiredHeightLocktimeKeyPair := KeyPair{
			Key: Key{
				KeyType: InputRequiredTimeLocktime,
				KeyData: nil,
			},
			Value: requiredHeightLocktimeBytes,
		}
		keyPairs = append(keyPairs, requiredHeightLocktimeKeyPair)
	}

	if i.IssuanceValue != 0 {
		issuanceValueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(issuanceValueBytes, uint64(i.IssuanceValue))
		issuanceValueKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceValue, nil),
			},
			Value: issuanceValueBytes,
		}
		keyPairs = append(keyPairs, issuanceValueKeyPair)
	}

	if i.IssuanceValueCommitment != nil {
		issuanceValueCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceValueCommitment, nil),
			},
			Value: i.IssuanceValueCommitment,
		}
		keyPairs = append(keyPairs, issuanceValueCommitmentKeyPair)
	}

	if i.IssuanceValueRangeproof != nil {
		issuanceValueRangeproofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceValueRangeproof, nil),
			},
			Value: i.IssuanceValueRangeproof,
		}
		keyPairs = append(keyPairs, issuanceValueRangeproofKeyPair)
	}

	if i.IssuanceInflationKeysRangeproof != nil {
		issuanceKeysRangeproofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceInflationKeysRangeproof, nil),
			},
			Value: i.IssuanceInflationKeysRangeproof,
		}
		keyPairs = append(keyPairs, issuanceKeysRangeproofKeyPair)
	}

	if i.PeginTx != nil {
		peginTxBytes, err := i.PeginTx.Serialize()
		if err != nil {
			return nil, err
		}

		peginTxKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputPeginTx, nil),
			},
			Value: peginTxBytes,
		}
		keyPairs = append(keyPairs, peginTxKeyPair)
	}

	if i.PeginTxoutProof != nil {
		peginTxoutProofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputPeginTxoutProof, nil),
			},
			Value: i.PeginTxoutProof,
		}
		keyPairs = append(keyPairs, peginTxoutProofKeyPair)
	}

	if i.PeginGenesisHash != nil {
		peginGenesisHashKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputPeginGenesis, nil),
			},
			Value: i.PeginGenesisHash,
		}
		keyPairs = append(keyPairs, peginGenesisHashKeyPair)
	}

	if i.PeginClaimScript != nil {
		peginClaimScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputPeginClaimScript, nil),
			},
			Value: i.PeginClaimScript,
		}
		keyPairs = append(keyPairs, peginClaimScriptKeyPair)
	}

	if i.PeginValue != 0 {
		var peginValueBytes []byte
		binary.LittleEndian.PutUint64(peginValueBytes, i.PeginValue)

		peginValueKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputPeginValue, nil),
			},
			Value: peginValueBytes,
		}
		keyPairs = append(keyPairs, peginValueKeyPair)
	}

	if i.PeginWitness != nil {
		peginWitnessKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputPeginWitness, nil),
			},
			Value: i.PeginWitness,
		}
		keyPairs = append(keyPairs, peginWitnessKeyPair)
	}

	if i.IssuanceInflationKeys != 0 {
		issuanceInflationKeysBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(issuanceInflationKeysBytes, i.IssuanceInflationKeys)

		issuanceInflationKeysKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceInflationKeys, nil),
			},
			Value: issuanceInflationKeysBytes,
		}
		keyPairs = append(keyPairs, issuanceInflationKeysKeyPair)
	}

	if i.IssuanceInflationKeysCommitment != nil {
		issuanceInflationKeysCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceInflationKeysCommitment, nil),
			},
			Value: i.IssuanceInflationKeysCommitment,
		}
		keyPairs = append(keyPairs, issuanceInflationKeysCommitmentKeyPair)
	}

	if i.IssuanceBlindingNonce != nil {
		issuanceBlindingNonceKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceBlindingNonce, nil),
			},
			Value: i.IssuanceBlindingNonce,
		}
		keyPairs = append(keyPairs, issuanceBlindingNonceKeyPair)
	}

	if i.IssuanceAssetEntropy != nil {
		issuanceAssetEntropyKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceAssetEntropy, nil),
			},
			Value: i.IssuanceAssetEntropy,
		}
		keyPairs = append(keyPairs, issuanceAssetEntropyKeyPair)
	}

	if i.UtxoRangeProof != nil {
		inUtxoRangeProofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputUtxoRangeProof, nil),
			},
			Value: i.UtxoRangeProof,
		}
		keyPairs = append(keyPairs, inUtxoRangeProofKeyPair)
	}

	if i.IssuanceBlindValueProof != nil {
		issuanceBlindValueProofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceBlindValueProof, nil),
			},
			Value: i.IssuanceBlindValueProof,
		}
		keyPairs = append(keyPairs, issuanceBlindValueProofKeyPair)
	}

	if i.IssuanceBlindInflationKeysProof != nil {
		issuanceBlindInflationKeysProofKeyPair := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(InputIssuanceBlindInflationKeysProof, nil),
			},
			Value: i.IssuanceBlindInflationKeysProof,
		}
		keyPairs = append(keyPairs, issuanceBlindInflationKeysProofKeyPair)
	}

	for _, v := range i.ProprietaryData {
		kp := KeyPair{
			Key: Key{
				KeyType: GlobalProprietary,
				KeyData: proprietaryKey(v.Subtype, v.KeyData),
			},
			Value: v.Value,
		}
		keyPairs = append(keyPairs, kp)
	}

	keyPairs = append(keyPairs, i.Unknowns...)

	return keyPairs, nil
}

func (i *Input) serialize(s *bufferutil.Serializer) error {
	inputKeyPairs, err := i.getKeyPairs()
	if err != nil {
		return err
	}

	for _, v := range inputKeyPairs {
		if err := v.serialize(s); err != nil {
			return err
		}
	}

	if err := s.WriteUint8(separator); err != nil {
		return err
	}

	return nil
}

func (i *Input) deserialize(buf *bytes.Buffer) error {
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
		case InputNonWitnessUtxo:
			if i.NonWitnessUtxo != nil {
				return ErrDuplicateKey
			}

			tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(kp.Value))
			if err != nil {
				return fmt.Errorf("invalid input non-witness utxo: %s", err)
			}

			i.NonWitnessUtxo = tx
		case InputWitnessUtxo:
			if i.WitnessUtxo != nil {
				return ErrDuplicateKey
			}

			txOut, err := readTxOut(kp.Value)
			if err != nil {
				return fmt.Errorf("invalid input witness utxo: %s", err)
			}

			i.WitnessUtxo = txOut
		case InputPartialSig:
			partialSignature := PartialSig{
				PubKey:    kp.Key.KeyData,
				Signature: kp.Value,
			}
			if !partialSignature.checkValid() {
				return ErrInInvalidPartialSignature
			}

			// Duplicate keys are not allowed
			for _, v := range i.PartialSigs {
				if bytes.Equal(v.PubKey, partialSignature.PubKey) {
					return ErrDuplicateKey
				}
			}

			i.PartialSigs = append(i.PartialSigs, partialSignature)
		case InputSighashType:
			if i.SigHashType != 0 {
				return ErrDuplicateKey
			}

			if len(kp.Value) != 4 {
				return ErrInInvalidSigHash
			}

			sigHashType := txscript.SigHashType(
				binary.LittleEndian.Uint32(kp.Value),
			)

			i.SigHashType = sigHashType
		case InputRedeemScript:
			if i.RedeemScript != nil {
				return ErrDuplicateKey
			}
			i.RedeemScript = kp.Value
		case InputWitnessScript:
			if i.WitnessScript != nil {
				return ErrDuplicateKey
			}
			i.WitnessScript = kp.Value
		case InputBip32Derivation:
			if !validatePubkey(kp.Key.KeyData) {
				return ErrInInvalidPubKey
			}
			master, derivationPath, err := readBip32Derivation(kp.Value)
			if err != nil {
				return fmt.Errorf("invalid input bip32 derivation path: %s", err)
			}

			// Duplicate keys are not allowed
			for _, x := range i.Bip32Derivation {
				if bytes.Equal(x.PubKey, kp.Key.KeyData) {
					return ErrDuplicateKey
				}
			}

			i.Bip32Derivation = append(
				i.Bip32Derivation,
				DerivationPathWithPubKey{
					PubKey:               kp.Key.KeyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)
		case InputFinalScriptsig:
			if i.FinalScriptSig != nil {
				return ErrDuplicateKey
			}
			i.FinalScriptSig = kp.Value
		case InputFinalScriptwitness:
			if i.FinalScriptWitness != nil {
				return ErrDuplicateKey
			}
			i.FinalScriptWitness = kp.Value
		case InputRipemd160:
			if i.Ripemd160Preimages == nil {
				i.Ripemd160Preimages = make(map[[20]byte][]byte)
			}

			var hash [20]byte
			copy(hash[:], kp.Key.KeyData[:])
			i.Ripemd160Preimages[hash] = kp.Value
		case InputSha256:
			if i.Sha256Preimages == nil {
				i.Sha256Preimages = make(map[[32]byte][]byte)
			}
			var hash [32]byte
			copy(hash[:], kp.Key.KeyData[:])
			i.Sha256Preimages[hash] = kp.Value
		case InputHash160:
			if i.Hash160Preimages == nil {
				i.Hash160Preimages = make(map[[20]byte][]byte)
			}
			var hash [20]byte
			copy(hash[:], kp.Key.KeyData[:])
			i.Hash160Preimages[hash] = kp.Value
		case InputHash256:
			if i.Hash256Preimages == nil {
				i.Hash256Preimages = make(map[[32]byte][]byte)
			}
			var hash [32]byte
			copy(hash[:], kp.Key.KeyData[:])
			i.Hash256Preimages[hash] = kp.Value
		case InputPreviousTxid:
			if i.PreviousTxid != nil {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 32 {
				return ErrInInvalidPreviousTxid
			}
			i.PreviousTxid = kp.Value
		case InputPreviousTxIndex:
			if i.PreviousTxIndex != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidPreviousTxIndex
			}
			i.PreviousTxIndex = binary.LittleEndian.Uint32(kp.Value)
		case InputSequence:
			if i.Sequence != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidSequence
			}
			i.Sequence = binary.LittleEndian.Uint32(kp.Value)
		case InputRequiredTimeLocktime:
			if i.RequiredTimeLocktime != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidRequiredLocktime
			}
			i.RequiredTimeLocktime = binary.LittleEndian.Uint32(kp.Value)
		case InputRequiredHeightLocktime:
			if i.RequiredHeightLocktime != 0 {
				return ErrDuplicateKey
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidRequiredHeightLocktime
			}
			i.RequiredHeightLocktime = binary.LittleEndian.Uint32(kp.Value)
		case GlobalProprietary:
			pd := ProprietaryData{}
			if err := pd.fromKeyPair(kp); err != nil {
				return err
			}

			if bytes.Equal(pd.Identifier, magicPrefix) {
				switch pd.Subtype {
				case InputIssuanceValue:
					if i.IssuanceValue != 0 {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 8 {
						return ErrInInvalidIssuanceValue
					}
					i.IssuanceValue = binary.LittleEndian.Uint64(kp.Value)
				case InputIssuanceValueCommitment:
					if i.IssuanceValueCommitment != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 33 {
						return ErrInInvalidIssuanceCommitment
					}
					i.IssuanceValueCommitment = kp.Value
				case InputIssuanceValueRangeproof:
					if i.IssuanceValueRangeproof != nil {
						return ErrDuplicateKey
					}
					i.IssuanceValueRangeproof = kp.Value
				case InputIssuanceInflationKeysRangeproof:
					if i.IssuanceInflationKeysRangeproof != nil {
						return ErrDuplicateKey
					}
					i.IssuanceInflationKeysRangeproof = kp.Value
				case InputPeginTx:
					if i.PeginTx != nil {
						return ErrDuplicateKey
					}
					tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(kp.Value))
					if err != nil {
						return fmt.Errorf("invalid input pegin tx: %s", err)
					}
					i.PeginTx = tx
				case InputPeginTxoutProof:
					if i.PeginTxoutProof != nil {
						return ErrDuplicateKey
					}
					i.PeginTxoutProof = kp.Value
				case InputPeginGenesis:
					if i.PeginGenesisHash != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 32 {
						return ErrInInvalidPeginGenesisHash
					}
					i.PeginGenesisHash = kp.Value
				case InputPeginClaimScript:
					if i.PeginClaimScript != nil {
						return ErrDuplicateKey
					}
					i.PeginClaimScript = kp.Value
				case InputPeginValue:
					if i.PeginValue != 0 {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 8 {
						return ErrInInvalidPeginValue
					}
					i.PeginValue = binary.LittleEndian.Uint64(kp.Value)
				case InputPeginWitness:
					if i.PeginWitness != nil {
						return ErrDuplicateKey
					}
					i.PeginWitness = kp.Value
				case InputIssuanceInflationKeys:
					if i.IssuanceInflationKeys != 0 {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 8 {
						return ErrInInvalidIssuanceInflationKeys
					}
					i.IssuanceInflationKeys = binary.LittleEndian.Uint64(kp.Value)
				case InputIssuanceInflationKeysCommitment:
					if i.IssuanceInflationKeysCommitment != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 33 {
						return ErrInInvalidIssuanceInflationKeysCommitment
					}
					i.IssuanceInflationKeysCommitment = kp.Value
				case InputIssuanceBlindingNonce:
					if i.IssuanceBlindingNonce != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 33 {
						return ErrInInvalidIssuanceBlindingNonce
					}
					i.IssuanceBlindingNonce = kp.Value
				case InputIssuanceAssetEntropy:
					if i.IssuanceAssetEntropy != nil {
						return ErrDuplicateKey
					}
					if len(kp.Value) != 32 {
						return ErrInInvalidIssuanceAssetEntropy
					}
					i.IssuanceAssetEntropy = kp.Value
				case InputUtxoRangeProof:
					if i.UtxoRangeProof != nil {
						return ErrDuplicateKey
					}
					i.UtxoRangeProof = kp.Value
				case InputIssuanceBlindValueProof:
					if i.IssuanceBlindValueProof != nil {
						return ErrDuplicateKey
					}
					i.IssuanceBlindValueProof = kp.Value
				case InputIssuanceBlindInflationKeysProof:
					if i.IssuanceBlindInflationKeysProof != nil {
						return ErrDuplicateKey
					}
					i.IssuanceBlindInflationKeysProof = kp.Value
				default:
					i.ProprietaryData = append(i.ProprietaryData, pd)
				}
			}
		default:
			i.Unknowns = append(i.Unknowns, kp)
		}
	}

	return i.SanityCheck()
}
