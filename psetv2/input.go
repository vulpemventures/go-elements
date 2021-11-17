package psetv2

import (
	"bytes"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"

	"github.com/vulpemventures/go-elements/elementsutil"

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
	ErrInvalidAssetCommitmentLength                 = errors.New("invalid asset commitment length")
	ErrInvalidTokenCommitmentLength                 = errors.New("invalid token commitment length")
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

func psetInputFromTxInput(input transaction.TxInput) (*Input, error) {
	previousOutputIndex := input.Index
	previousTxid := input.Hash
	sequence := input.Sequence

	var issuanceValue *int64
	var issuanceCommitment []byte
	var tokenValue *int64
	var tokenCommitment []byte
	var issuanceBlindingNonce []byte
	var issuanceAssetEntropy []byte
	if input.HasIssuance() {
		//if non confidential
		if len(input.Issuance.AssetAmount) == 9 && input.Issuance.AssetAmount[0] == 1 {
			i, err := elementsutil.ElementsToSatoshiValue(input.Issuance.AssetAmount)
			if err != nil {
				return nil, err
			}
			iv := int64(i)
			issuanceValue = &iv
		} else {
			if len(input.Issuance.AssetAmount) != 33 {
				return nil, ErrInvalidAssetCommitmentLength
			}

			issuanceCommitment = input.Issuance.AssetAmount
		}

		//TODO: verify if token is inflation key
		if len(input.Issuance.TokenAmount) == 9 && input.Issuance.TokenAmount[0] == 1 {
			t, err := elementsutil.ElementsToSatoshiValue(input.Issuance.TokenAmount)
			if err != nil {
				return nil, err
			}
			tv := int64(t)
			tokenValue = &tv
		} else {
			if len(input.Issuance.TokenAmount) != 33 {
				return nil, ErrInvalidAssetCommitmentLength
			}

			tokenCommitment = input.Issuance.TokenAmount
		}

		if input.Issuance.IsReissuance() {
			issuanceBlindingNonce = input.Issuance.AssetBlindingNonce
		}

		if !bytes.Equal(input.Issuance.AssetEntropy, transaction.Zero[:]) {
			issuanceAssetEntropy = input.Issuance.AssetEntropy
		}
	}

	var peginWitness []byte
	if input.IsPegin {
		//TODO: verify bellow
		s, err := bufferutil.NewSerializer(nil)
		if err != nil {
			return nil, err
		}

		if err := s.WriteVector(input.PeginWitness); err != nil {
			return nil, err
		}

		peginWitness = s.Bytes()
	}

	return &Input{
		previousTxid:                    previousTxid,
		previousOutputIndex:             &previousOutputIndex,
		sequence:                        &sequence,
		issuanceValue:                   issuanceValue,
		issuanceValueCommitment:         issuanceCommitment,
		peginWitness:                    peginWitness,
		issuanceInflationKeys:           tokenValue,
		issuanceInflationKeysCommitment: tokenCommitment,
		issuanceBlindingNonce:           issuanceBlindingNonce,
		issuanceAssetEntropy:            issuanceAssetEntropy,
	}, nil
}

func (i *Input) GetUtxo() *transaction.TxOutput {
	var txOut *transaction.TxOutput
	if i.nonWitnessUtxo != nil {
		txOut = i.nonWitnessUtxo.Outputs[*i.previousOutputIndex]
	} else if i.witnessUtxo != nil {
		txOut = i.witnessUtxo
	}

	return txOut
}
