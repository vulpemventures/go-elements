package psetv2

import (
	"bytes"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/vulpemventures/go-elements/transaction"
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
	PsbtElementsInUtxoRangeproof                  = 0x0e
	PsbtElementsInIssuanceBlindValueProof         = 0x0f
	PsbtElementsInIssuanceBlindInflationKeysProof = 0x10
)

type Input struct {
	// The non-witness transaction this input spends from. Should only be
	// [std::option::Option::Some] for inputs which spend non-segwit outputs or
	// if it is unknown whether an input spends a segwit output.
	nonWitnessUtxo transaction.Transaction
	// The transaction output this input spends from. Should only be
	// [std::option::Option::Some] for inputs which spend segwit outputs,
	// including P2SH embedded ones.
	witnessUtxo transaction.TxOutput
	// A map from public keys to their corresponding signature as would be
	// pushed to the stack from a scriptSig or witness.
	partialSigs []*psbt.PartialSig
	// The sighash type to be used for this input. Signatures for this input
	// must use the sighash type.
	sighashType txscript.SigHashType
	// The redeem script for this input.
	redeemScript []byte
	/// The witness script for this input.
	witnessScript []byte
	// A map from public keys needed to sign this input to their corresponding
	// master key fingerprints and derivation paths.
	bip32Derivation []*psbt.Bip32Derivation
	// The finalized, fully-constructed scriptSig with signatures and any other
	// scripts necessary for this input to pass validation.
	finalScriptSig []byte
	// The finalized, fully-constructed scriptWitness with signatures and any
	// other scripts necessary for this input to pass validation.
	finalScriptWitness []byte
	// RIPEMD160 hash to preimage map
	ripemd160Preimages map[[20]byte][]byte
	// SHA256 hash to preimage map
	sha256Preimages map[[20]byte][]byte
	// HSAH160 hash to preimage map
	hash160Preimages map[[20]byte][]byte
	// HAS256 hash to preimage map
	hash256Preimages map[[20]byte][]byte
	// (PSET2) Prevout TXID of the input
	previousTxid [32]byte
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
	issuanceValue []byte
	// Issuance value rangeproof
	issuanceValueRangeproof []byte
	// Issuance keys rangeproof
	issuanceKeysRangeproof []byte
	// Pegin Transaction. Should be a bitcoin::Transaction
	peginTx transaction.Transaction
	// Pegin Transaction proof
	// TODO: Look for Merkle proof structs
	peginTxoutProof []byte
	// Pegin genesis hash
	peginGenesisHash [32]byte
	// Claim script
	peginClaimScript []byte
	// Pegin Value
	peginValue uint64
	// Pegin Witness
	peginWitness []byte
	/// Issuance inflation keys
	issuanceInflationKeys []byte
	// Issuance blinding nonce
	issuanceBlindingNonce [32]byte
	// Issuance asset entropy
	issuanceAssetEntropy [32]byte
	// input utxo rangeproof
	inUtxoRangeproof []byte
	// Other fields
	proprietaryData []proprietaryData
	// Unknown key-value pairs for this input.
	unknown []keyPair
}

func deserializeInputs(buf *bytes.Buffer) ([]Input, error) {
	return nil, nil
}
