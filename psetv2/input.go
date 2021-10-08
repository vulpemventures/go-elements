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
	PsetInNonWitnessUtxo         = 0x00 //BIP 174
	PsetInWitnessUtxo            = 0x01 //BIP 174
	PsetInPartialSig             = 0x02 //BIP 174
	PsetInSighashType            = 0x03 //BIP 174
	PsetInRedeemScript           = 0x04 //BIP 174
	PsetInWitnessScript          = 0x05 //BIP 174
	PsetInBip32Derivation        = 0x06 //BIP 174
	PsetInFinalScriptsig         = 0x07 //BIP 174
	PsetInFinalScriptwitness     = 0x08 //BIP 174
	PsbtInPorCommitment          = 0x09 //BIP 127
	PsetInRipemd160              = 0x0a //BIP 174
	PsetInSha256                 = 0x0b //BIP 174
	PsetInHash160                = 0x0c //BIP 174
	PsetInHash256                = 0x0d //BIP 174
	PsetInPreviousTxid           = 0x0e //BIP 370
	PsetInOutputIndex            = 0x0f //BIP 370
	PsetInSequence               = 0x10 //BIP 370
	PsetInRequiredTimeLocktime   = 0x11 //BIP 370
	PsetInRequiredHeightLocktime = 0x12 //BIP 370
	PsbtInTapKeySig              = 0x13 //BIP 371
	PsbtInTapScriptSig           = 0x14 //BIP 371
	PsbtInTapLeafScript          = 0x15 //BIP 371
	PsbtInTapBip32Derivation     = 0x16 //BIP 371
	PsbtInTapInternalKey         = 0x17 //BIP 371
	PsbtInTapMerkleRoot          = 0x18 //BIP 371
	PsetInProprietary            = 0xFC //BIP 174

	//Elements Proprietary types
	PsbtElementsInIssuanceValue                   = 0x00
	PsbtElementsInIssuanceValueCommitment         = 0x01
	PsbtElementsInIssuanceValueRangeproof         = 0x02
	PsbtElementsInIssuanceKeysRangeproof          = 0x03
	PsbtElementsInPegInTx                         = 0x04
	PsbtElementsInPegInTxoutProof                 = 0x05
	PsbtElementsInPegInGenesis                    = 0x06
	PsbtElementsInPegInClaimScript                = 0x07
	PsbtElementsInPegInValue                      = 0x08
	PsbtElementsInPegInWitness                    = 0x09
	PsbtElementsInIssuanceInflationKeys           = 0x0a
	PsbtElementsInIssuanceInflationKeysCommitment = 0x0b
	PsbtElementsInIssuanceBlindingNonce           = 0x0c
	PsbtElementsInIssuanceAssetEntropy            = 0x0d
	PsbtElementsInUtxoRangeProof                  = 0x0e
	PsbtElementsInIssuanceBlindValueProof         = 0x0f
	PsbtElementsInIssuanceBlindInflationKeysProof = 0x10
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
	sigHashType txscript.SigHashType
	// The redeem script for this input.
	redeemScript []byte
	/// The witness script for this input.
	witnessScript []byte
	// A map from public keys needed to sign this input to their corresponding
	// master key fingerprints and derivation paths.
	bip32Derivation []Bip32Derivation
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
	previousOutputIndex uint32
	// (PSET2) Sequence number. If omitted, defaults to 0xffffffff
	sequence uint32
	// (PSET2) Minimum required locktime, as a UNIX timestamp. If present, must be greater than or equal to 500000000
	requiredTimeLocktime uint32
	// (PSET2) Minimum required locktime, as a blockheight. If present, must be less than 500000000
	requiredHeightLocktime uint32
	// Proprietary key-value pairs for this input.
	// The issuance value
	issuanceValue int64
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
	peginValue int64
	// Pegin Witness
	peginWitness []byte
	// Issuance inflation keys
	issuanceInflationKeys int64
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

func deserializeInput(buf *bytes.Buffer) (*Input, error) {
	input := Input{
		partialSigs:     make([]PartialSig, 0),
		bip32Derivation: make([]Bip32Derivation, 0),
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
		case PsetInNonWitnessUtxo:
			tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(kp.value))
			if err != nil {
				return nil, err
			}

			input.nonWitnessUtxo = tx
		case PsetInWitnessUtxo:
			txOut, err := readTxOut(kp.value)
			if err != nil {
				return nil, err
			}

			input.witnessUtxo = txOut
		case PsetInPartialSig:
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
		case PsetInSighashType:
			if len(kp.value) != 4 {
				return nil, ErrInvalidKeydata
			}

			sigHashType := txscript.SigHashType(
				binary.LittleEndian.Uint32(kp.value),
			)

			input.sigHashType = sigHashType
		case PsetInRedeemScript:
			input.redeemScript = kp.value
		case PsetInWitnessScript:
			input.witnessScript = kp.value
		case PsetInBip32Derivation:
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
				Bip32Derivation{
					PubKey:               kp.key.keyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)
		case PsetInFinalScriptsig:
			input.finalScriptSig = kp.value
		case PsetInFinalScriptwitness:
			input.finalScriptWitness = kp.value
		case PsetInRipemd160:
			ripemd160Preimages := make(map[[20]byte][]byte)
			var hash [20]byte
			copy(hash[:], kp.key.keyData[:])
			ripemd160Preimages[hash] = kp.value
			input.ripemd160Preimages = ripemd160Preimages
		case PsetInSha256:
			sha256Preimages := make(map[[32]byte][]byte)
			var hash [32]byte
			copy(hash[:], kp.key.keyData[:])
			sha256Preimages[hash] = kp.value
			input.sha256Preimages = sha256Preimages
		case PsetInHash160:
			hash160Preimages := make(map[[20]byte][]byte)
			var hash [20]byte
			copy(hash[:], kp.key.keyData[:])
			hash160Preimages[hash] = kp.value
			input.hash160Preimages = hash160Preimages
		case PsetInHash256:
			hash256Preimages := make(map[[32]byte][]byte)
			var hash [32]byte
			copy(hash[:], kp.key.keyData[:])
			input.hash256Preimages = hash256Preimages
		case PsetInPreviousTxid:
			previousTxid := kp.value
			if len(previousTxid) != 32 {
				return nil, ErrInvalidPrevTxIdLength
			}

			input.previousTxid = previousTxid
			prevTxIDFound = true
		case PsetInOutputIndex:
			input.previousOutputIndex = binary.LittleEndian.Uint32(kp.value)
			outputIndexFound = true
		case PsetInSequence:
			input.sequence = binary.LittleEndian.Uint32(kp.value)
		case PsetInRequiredTimeLocktime:
			input.requiredTimeLocktime = binary.LittleEndian.Uint32(kp.value)
		case PsetInRequiredHeightLocktime:
			input.requiredHeightLocktime = binary.LittleEndian.Uint32(kp.value)
		case PsbtGlobalProprietary:
			pd := &proprietaryData{}
			if err := pd.proprietaryDataFromKeyPair(*kp); err != nil {
				return nil, err
			}

			if bytes.Equal(pd.identifier, psetMagic) {
				switch pd.subtype {
				case PsbtElementsInIssuanceValue:
					input.issuanceValue = int64(binary.LittleEndian.Uint64(kp.value))
				case PsbtElementsInIssuanceValueCommitment:
					issuanceValueCommitment := kp.value
					if len(issuanceValueCommitment) != 33 {
						return nil, ErrInvalidIssuanceValueCommitmentLength
					}

					input.issuanceValueCommitment = issuanceValueCommitment
				case PsbtElementsInIssuanceValueRangeproof:
					input.issuanceValueRangeproof = kp.value
				case PsbtElementsInIssuanceKeysRangeproof:
					input.issuanceKeysRangeproof = kp.value
				case PsbtElementsInPegInTx:
					tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(kp.value))
					if err != nil {
						return nil, err
					}

					input.peginTx = tx
				case PsbtElementsInPegInTxoutProof:
					input.peginTxoutProof = kp.value
				case PsbtElementsInPegInGenesis:
					peginGenesisHash := kp.value[:]
					if len(peginGenesisHash) != 32 {
						return nil, ErrInvalidPeginGenesisHashLength
					}

					input.peginGenesisHash = peginGenesisHash
				case PsbtElementsInPegInClaimScript:
					input.peginClaimScript = kp.value
				case PsbtElementsInPegInValue:
					input.peginValue = int64(binary.LittleEndian.Uint64(kp.value))
				case PsbtElementsInPegInWitness:
					input.peginWitness = kp.value
				case PsbtElementsInIssuanceInflationKeys:
					input.issuanceInflationKeys = int64(binary.LittleEndian.Uint64(kp.value))
				case PsbtElementsInIssuanceInflationKeysCommitment:
					issuanceInflationKeysCommitment := kp.value[:]
					if len(issuanceInflationKeysCommitment) != 33 {
						return nil, ErrInvalidIssuanceInflationKeysCommitmentLength
					}

					input.issuanceInflationKeysCommitment = issuanceInflationKeysCommitment
				case PsbtElementsInIssuanceBlindingNonce:
					issuanceBlindingNonce := kp.value[:]
					if len(issuanceBlindingNonce) != 32 {
						return nil, ErrInvalidIssuanceBlindingNonceLength
					}

					input.issuanceBlindingNonce = issuanceBlindingNonce
				case PsbtElementsInIssuanceAssetEntropy:
					issuanceAssetEntropy := kp.value[:]
					if len(issuanceAssetEntropy) != 32 {
						return nil, ErrInvalidIssuanceAssetEntropyLength
					}

					input.issuanceAssetEntropy = issuanceAssetEntropy
				case PsbtElementsInUtxoRangeProof:
					input.inUtxoRangeProof = kp.value
				case PsbtElementsInIssuanceBlindValueProof:
					input.issuanceBlindValueProof = kp.value
				case PsbtElementsInIssuanceBlindInflationKeysProof:
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
