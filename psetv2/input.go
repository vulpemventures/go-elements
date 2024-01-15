package psetv2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/taproot"
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
	InputExplicitValue                   = 0x11
	InputValueProof                      = 0x12
	InputExplicitAsset                   = 0x13
	InputAssetProof                      = 0x14
	InputBlindedIssuanceValue            = 0x15
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
	ErrInInvalidTapKeySig = fmt.Errorf(
		"invalid input taproot key signature length",
	)
	ErrInInvalidTapScriptSigKeyData = fmt.Errorf(
		"invalid input taproot script signature key data length",
	)
	ErrInInvalidTapScriptSigSignature = fmt.Errorf(
		"invalid input taproot script signature",
	)
	ErrInInvalidTapLeafScriptKeyData = fmt.Errorf(
		"invalid input taproot leaf script key data length",
	)
	ErrInInvalidTapLeafScriptVersion = fmt.Errorf(
		"invalid input taproot leaf script version",
	)
	ErrInInvalidTapLeafScript = fmt.Errorf(
		"invalid input taproot leaf script",
	)
	ErrInInvalidTapBip32DerivationKeyData = fmt.Errorf(
		"invalid input taproot bip32 derivation pubkey length",
	)
	ErrInInvalidTapBip32Derivation = fmt.Errorf(
		"invalid input taproot bip32 derivation",
	)
	ErrInInvalidTapInternalKey = fmt.Errorf(
		"invalid input taproot internal key",
	)
	ErrInInvalidTapMerkleRoot = fmt.Errorf(
		"invalid input taproot merkle root",
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
	ErrInMissingIssuanceBlindValueProof = fmt.Errorf(
		"missing input issuance value commitment or blind proof",
	)
	ErrInMissingIssuanceBlindInflationKeysProof = fmt.Errorf(
		"missing input issuance inflation keys commitment or blind proof",
	)
	ErrInInvalidLocktime       = fmt.Errorf("invalid input locktime")
	ErrInInvalidNonWitnessUtxo = fmt.Errorf(
		"non-witness utxo hash does not match input txid",
	)
	ErrInInvalidPeginWitness = fmt.Errorf("invalid input pegin witness")
	ErrInInvalidPeginTx      = fmt.Errorf("invalid input pegin tx")
	ErrInDuplicatedField     = func(field string) error {
		return fmt.Errorf("duplicated input %s", field)
	}
	ErrInInvalidExplicitValue        = fmt.Errorf("invalid input explicit value")
	ErrInInvalidExplicitAsset        = fmt.Errorf("invalid input explicit asset")
	ErrInInvalidBlindedIssuanceValue = fmt.Errorf("invalid input blinded issuance value")
)

type TapLeafScript struct {
	taproot.TapElementsLeaf
	ControlBlock taproot.ControlBlock
}

func NewTapLeafScript(leafProof taproot.TapscriptElementsProof, internalKey *secp256k1.PublicKey) TapLeafScript {
	controlBlock := leafProof.ToControlBlock(internalKey)
	return TapLeafScript{
		TapElementsLeaf: leafProof.TapElementsLeaf,
		ControlBlock:    controlBlock,
	}
}

func (t *TapLeafScript) sanityCheck() error {
	if len(t.Script) == 0 {
		return ErrInInvalidTapLeafScript
	}
	return nil
}

type TapScriptSig struct {
	PartialSig
	LeafHash []byte
}

func (t *TapScriptSig) sanityCheck() error {
	if len(t.PubKey) != 32 {
		return ErrInInvalidTapScriptSigSignature
	}
	if len(t.Signature) != 64 && len(t.Signature) != 65 {
		return ErrInInvalidTapScriptSigSignature
	}
	return nil
}

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
	PeginTx                         *wire.MsgTx
	PeginTxoutProof                 []byte
	PeginGenesisHash                []byte
	PeginClaimScript                []byte
	PeginValue                      uint64
	PeginWitness                    [][]byte
	IssuanceInflationKeys           uint64
	IssuanceInflationKeysCommitment []byte
	IssuanceBlindingNonce           []byte
	IssuanceAssetEntropy            []byte
	UtxoRangeProof                  []byte
	IssuanceBlindValueProof         []byte
	IssuanceBlindInflationKeysProof []byte
	ExplicitValue                   uint64
	ValueProof                      []byte
	ExplicitAsset                   []byte
	AssetProof                      []byte
	BlindedIssuance                 *bool
	ProprietaryData                 []ProprietaryData
	TapKeySig                       []byte
	TapScriptSig                    []TapScriptSig
	TapLeafScript                   []TapLeafScript
	TapBip32Derivation              []TapDerivationPathWithPubKey
	TapInternalKey                  []byte
	TapMerkleRoot                   []byte
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
	issuanceValueCommitSet := len(i.IssuanceValueCommitment) > 0
	issuanceBlindValueProofSet := len(i.IssuanceBlindValueProof) > 0
	if (i.IssuanceValue) > 0 &&
		issuanceValueCommitSet != issuanceBlindValueProofSet {
		return ErrInMissingIssuanceBlindValueProof
	}
	issuanceTokenCommitSet := len(i.IssuanceInflationKeysCommitment) > 0
	issuanceBlindTokenProofSet := len(i.IssuanceBlindInflationKeysProof) > 0
	if (i.IssuanceInflationKeys) > 0 &&
		issuanceTokenCommitSet != issuanceBlindTokenProofSet {
		return ErrInMissingIssuanceBlindInflationKeysProof
	}

	if i.ExplicitValue > 0 && len(i.ValueProof) == 0 || i.ExplicitValue == 0 && len(i.ValueProof) > 0 {
		return ErrInInvalidExplicitValue
	}

	if len(i.ExplicitAsset) > 0 && len(i.AssetProof) == 0 || len(i.ExplicitAsset) == 0 && len(i.AssetProof) > 0 {
		return ErrInInvalidExplicitAsset
	}

	if len(i.TapInternalKey) > 0 && len(i.TapInternalKey) != 32 {
		return ErrInInvalidTapInternalKey
	}

	if len(i.TapMerkleRoot) > 0 && len(i.TapMerkleRoot) != 32 {
		return ErrInInvalidTapMerkleRoot
	}

	if len(i.TapKeySig) > 0 && len(i.TapKeySig) != 64 && len(i.TapKeySig) != 65 {
		return ErrInInvalidTapKeySig
	}

	for _, leaf := range i.TapLeafScript {
		if err := leaf.sanityCheck(); err != nil {
			return err
		}
	}

	for _, scriptSig := range i.TapScriptSig {
		if err := scriptSig.sanityCheck(); err != nil {
			return err
		}
	}

	for _, derivation := range i.TapBip32Derivation {
		if err := derivation.sanityCheck(); err != nil {
			return err
		}
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
	if len(i.IssuanceBlindingNonce) <= 0 {
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

func (i *Input) isBlindedIssuance() bool {
	if i.BlindedIssuance == nil {
		return true
	}
	return *i.BlindedIssuance
}

func (i *Input) GetIssuanceInflationKeysHash() []byte {
	// return nil if there is no issuance (or reissuance) object attached to the input
	if !i.HasIssuance() {
		return nil
	}

	issuance := transaction.NewTxIssuanceFromEntropy(i.IssuanceAssetEntropy)
	if !i.HasReissuance() {
		issuance = transaction.NewTxIssuanceFromContractHash(i.IssuanceAssetEntropy)
		issuance.GenerateEntropy(i.PreviousTxid, i.PreviousTxIndex)
	}

	flag := NonConfidentialReissuanceTokenFlag
	if i.isBlindedIssuance() {
		flag = ConfidentialReissuanceTokenFlag
	}

	assetHash, _ := issuance.GenerateReissuanceToken(flag)
	return assetHash
}

func (i *Input) GetUtxo() *transaction.TxOutput {
	if i.WitnessUtxo == nil && i.NonWitnessUtxo == nil {
		return nil
	}
	utxo := i.WitnessUtxo
	if utxo == nil {
		utxo = i.NonWitnessUtxo.Outputs[i.PreviousTxIndex]
	}
	if utxo != nil {
		utxo.RangeProof = i.UtxoRangeProof
	}
	return utxo
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

		witnessUtxoKeyPair := KeyPair{
			Key: Key{
				KeyType: InputWitnessUtxo,
				KeyData: nil,
			},
			Value: witnessUtxoBytes,
		}
		keyPairs = append(keyPairs, witnessUtxoKeyPair)
	}

	if len(i.PartialSigs) > 0 {
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

	if len(i.RedeemScript) > 0 {
		redeemScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: InputRedeemScript,
				KeyData: nil,
			},
			Value: i.RedeemScript,
		}
		keyPairs = append(keyPairs, redeemScriptKeyPair)
	}

	if len(i.WitnessScript) > 0 {
		witnessScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: InputWitnessScript,
				KeyData: nil,
			},
			Value: i.WitnessScript,
		}
		keyPairs = append(keyPairs, witnessScriptKeyPair)
	}

	if len(i.Bip32Derivation) > 0 {
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

	if len(i.FinalScriptSig) > 0 {
		finalScriptSigKeyPair := KeyPair{
			Key: Key{
				KeyType: InputFinalScriptsig,
				KeyData: nil,
			},
			Value: i.FinalScriptSig,
		}
		keyPairs = append(keyPairs, finalScriptSigKeyPair)
	}

	if len(i.FinalScriptWitness) > 0 {
		finalScriptWitnessKeyPair := KeyPair{
			Key: Key{
				KeyType: InputFinalScriptwitness,
				KeyData: nil,
			},
			Value: i.FinalScriptWitness,
		}
		keyPairs = append(keyPairs, finalScriptWitnessKeyPair)
	}

	if len(i.Ripemd160Preimages) > 0 {
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

	if len(i.Sha256Preimages) > 0 {
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

	if len(i.Hash160Preimages) > 0 {
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

	if len(i.Hash256Preimages) > 0 {
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

	if i.Sequence > 0 {
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
	}

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
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceValue, nil),
			},
			Value: issuanceValueBytes,
		}
		keyPairs = append(keyPairs, issuanceValueKeyPair)
	}

	if len(i.IssuanceValueCommitment) > 0 {
		issuanceValueCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceValueCommitment, nil),
			},
			Value: i.IssuanceValueCommitment,
		}
		keyPairs = append(keyPairs, issuanceValueCommitmentKeyPair)
	}

	if len(i.IssuanceValueRangeproof) > 0 {
		issuanceValueRangeproofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceValueRangeproof, nil),
			},
			Value: i.IssuanceValueRangeproof,
		}
		keyPairs = append(keyPairs, issuanceValueRangeproofKeyPair)
	}

	if len(i.IssuanceInflationKeysRangeproof) > 0 {
		issuanceKeysRangeproofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceInflationKeysRangeproof, nil),
			},
			Value: i.IssuanceInflationKeysRangeproof,
		}
		keyPairs = append(keyPairs, issuanceKeysRangeproofKeyPair)
	}

	if i.PeginTx != nil {
		buf := bytes.NewBuffer(nil)
		if err := i.PeginTx.BtcEncode(
			buf, wire.ProtocolVersion, wire.LatestEncoding,
		); err != nil {
			return nil, err
		}

		peginTxKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputPeginTx, nil),
			},
			Value: buf.Bytes(),
		}
		keyPairs = append(keyPairs, peginTxKeyPair)
	}

	if len(i.PeginTxoutProof) > 0 {
		peginTxoutProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputPeginTxoutProof, nil),
			},
			Value: i.PeginTxoutProof,
		}
		keyPairs = append(keyPairs, peginTxoutProofKeyPair)
	}

	if len(i.PeginGenesisHash) > 0 {
		peginGenesisHashKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputPeginGenesis, nil),
			},
			Value: i.PeginGenesisHash,
		}
		keyPairs = append(keyPairs, peginGenesisHashKeyPair)
	}

	if len(i.PeginClaimScript) > 0 {
		peginClaimScriptKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
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
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputPeginValue, nil),
			},
			Value: peginValueBytes,
		}
		keyPairs = append(keyPairs, peginValueKeyPair)
	}

	if len(i.PeginWitness) > 0 {
		s := bufferutil.NewSerializer(nil)
		if err := s.WriteVector(i.PeginWitness); err != nil {
			return nil, err
		}
		peginWitnessKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputPeginWitness, nil),
			},
			Value: s.Bytes(),
		}
		keyPairs = append(keyPairs, peginWitnessKeyPair)
	}

	if i.IssuanceInflationKeys != 0 {
		issuanceInflationKeysBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(issuanceInflationKeysBytes, i.IssuanceInflationKeys)

		issuanceInflationKeysKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceInflationKeys, nil),
			},
			Value: issuanceInflationKeysBytes,
		}
		keyPairs = append(keyPairs, issuanceInflationKeysKeyPair)
	}

	if len(i.IssuanceInflationKeysCommitment) > 0 {
		issuanceInflationKeysCommitmentKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceInflationKeysCommitment, nil),
			},
			Value: i.IssuanceInflationKeysCommitment,
		}
		keyPairs = append(keyPairs, issuanceInflationKeysCommitmentKeyPair)
	}

	if len(i.IssuanceBlindingNonce) > 0 {
		issuanceBlindingNonceKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceBlindingNonce, nil),
			},
			Value: i.IssuanceBlindingNonce,
		}
		keyPairs = append(keyPairs, issuanceBlindingNonceKeyPair)
	}

	if len(i.IssuanceAssetEntropy) > 0 {
		issuanceAssetEntropyKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceAssetEntropy, nil),
			},
			Value: i.IssuanceAssetEntropy,
		}
		keyPairs = append(keyPairs, issuanceAssetEntropyKeyPair)
	}

	if len(i.UtxoRangeProof) > 0 {
		inUtxoRangeProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputUtxoRangeProof, nil),
			},
			Value: i.UtxoRangeProof,
		}
		keyPairs = append(keyPairs, inUtxoRangeProofKeyPair)
	}

	if len(i.IssuanceBlindValueProof) > 0 {
		issuanceBlindValueProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceBlindValueProof, nil),
			},
			Value: i.IssuanceBlindValueProof,
		}
		keyPairs = append(keyPairs, issuanceBlindValueProofKeyPair)
	}

	if len(i.IssuanceBlindInflationKeysProof) > 0 {
		issuanceBlindInflationKeysProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputIssuanceBlindInflationKeysProof, nil),
			},
			Value: i.IssuanceBlindInflationKeysProof,
		}
		keyPairs = append(keyPairs, issuanceBlindInflationKeysProofKeyPair)
	}

	if i.ExplicitValue != 0 {
		explicitValueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(explicitValueBytes, i.ExplicitValue)

		explicitValueKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputExplicitValue, nil),
			},
			Value: explicitValueBytes,
		}
		keyPairs = append(keyPairs, explicitValueKeyPair)
	}

	if len(i.ValueProof) > 0 {
		valueProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputValueProof, nil),
			},
			Value: i.ValueProof,
		}
		keyPairs = append(keyPairs, valueProofKeyPair)
	}

	if len(i.ExplicitAsset) > 0 {
		explicitAssetKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputExplicitAsset, nil),
			},
			Value: i.ExplicitAsset,
		}
		keyPairs = append(keyPairs, explicitAssetKeyPair)
	}

	if len(i.AssetProof) > 0 {
		assetProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputAssetProof, nil),
			},
			Value: i.AssetProof,
		}
		keyPairs = append(keyPairs, assetProofKeyPair)
	}

	if i.BlindedIssuance != nil {
		blindedIssuance := []byte{0}
		if *i.BlindedIssuance {
			blindedIssuance = []byte{1}
		}
		assetProofKeyPair := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
				KeyData: proprietaryKey(InputBlindedIssuanceValue, nil),
			},
			Value: blindedIssuance,
		}
		keyPairs = append(keyPairs, assetProofKeyPair)
	}

	if len(i.TapKeySig) > 0 {
		kp := KeyPair{
			Key: Key{
				KeyType: InputTapKeySig,
				KeyData: nil,
			},
			Value: i.TapKeySig,
		}
		keyPairs = append(keyPairs, kp)
	}

	for _, tapScriptSig := range i.TapScriptSig {
		kp := KeyPair{
			Key: Key{
				KeyType: InputTapScriptSig,
				KeyData: append(tapScriptSig.PubKey, tapScriptSig.LeafHash...),
			},
			Value: tapScriptSig.Signature,
		}
		keyPairs = append(keyPairs, kp)
	}

	for _, tapLeafScript := range i.TapLeafScript {
		controlBlockBytes, err := tapLeafScript.ControlBlock.ToBytes()
		if err != nil {
			return nil, err
		}

		kp := KeyPair{
			Key: Key{
				KeyType: InputTapLeafScript,
				KeyData: controlBlockBytes,
			},
			Value: append(tapLeafScript.Script, byte(tapLeafScript.LeafVersion)),
		}
		keyPairs = append(keyPairs, kp)
	}

	for _, tapBip32Derivation := range i.TapBip32Derivation {
		serializer := bufferutil.NewSerializer(nil)
		if err := serializer.WriteVarInt(uint64(len(tapBip32Derivation.LeafHashes))); err != nil {
			return nil, err
		}
		for _, leafHash := range tapBip32Derivation.LeafHashes {
			if err := serializer.WriteSlice(leafHash[:]); err != nil {
				return nil, err
			}
		}
		encodedDerivation := SerializeBIP32Derivation(tapBip32Derivation.MasterKeyFingerprint, tapBip32Derivation.Bip32Path)
		if err := serializer.WriteSlice(encodedDerivation); err != nil {
			return nil, err
		}

		kp := KeyPair{
			Key: Key{
				KeyType: InputTapBip32Derivation,
				KeyData: tapBip32Derivation.PubKey,
			},
			Value: serializer.Bytes(),
		}

		keyPairs = append(keyPairs, kp)
	}

	if len(i.TapInternalKey) > 0 {
		kp := KeyPair{
			Key: Key{
				KeyType: InputTapInternalKey,
				KeyData: nil,
			},
			Value: i.TapInternalKey,
		}
		keyPairs = append(keyPairs, kp)
	}

	if len(i.TapMerkleRoot) > 0 {
		kp := KeyPair{
			Key: Key{
				KeyType: InputTapMerkleRoot,
				KeyData: nil,
			},
			Value: i.TapMerkleRoot,
		}
		keyPairs = append(keyPairs, kp)
	}

	for _, v := range i.ProprietaryData {
		kp := KeyPair{
			Key: Key{
				KeyType: PsetProprietary,
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
				return ErrInDuplicatedField("non-witness utxo")
			}

			tx, err := transaction.NewTxFromBuffer(bytes.NewBuffer(kp.Value))
			if err != nil {
				return fmt.Errorf("invalid input non-witness utxo: %s", err)
			}

			i.NonWitnessUtxo = tx
		case InputWitnessUtxo:
			if i.WitnessUtxo != nil {
				return ErrInDuplicatedField("witness utxo")
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
					return ErrInDuplicatedField("partial sig")
				}
			}

			i.PartialSigs = append(i.PartialSigs, partialSignature)
		case InputSighashType:
			if i.SigHashType != 0 {
				return ErrInDuplicatedField("sighash type")
			}

			if len(kp.Value) != 4 {
				return ErrInInvalidSigHash
			}

			sigHashType := txscript.SigHashType(
				binary.LittleEndian.Uint32(kp.Value),
			)

			i.SigHashType = sigHashType
		case InputRedeemScript:
			if len(i.RedeemScript) > 0 {
				return ErrInDuplicatedField("redeem script")
			}
			i.RedeemScript = kp.Value
		case InputWitnessScript:
			if len(i.WitnessScript) > 0 {
				return ErrInDuplicatedField("witness script")
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
					return ErrInDuplicatedField("bip32 derivation")
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
			if len(i.FinalScriptSig) > 0 {
				return ErrInDuplicatedField("final scriptsig")
			}
			i.FinalScriptSig = kp.Value
		case InputFinalScriptwitness:
			if len(i.FinalScriptWitness) > 0 {
				return ErrInDuplicatedField("final script witness")
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
			if len(i.PreviousTxid) > 0 {
				return ErrInDuplicatedField("previous txid")
			}
			if len(kp.Value) != 32 {
				return ErrInInvalidPreviousTxid
			}
			i.PreviousTxid = kp.Value
		case InputPreviousTxIndex:
			if i.PreviousTxIndex != 0 {
				return ErrInDuplicatedField("previous txindex")
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidPreviousTxIndex
			}
			i.PreviousTxIndex = binary.LittleEndian.Uint32(kp.Value)
		case InputSequence:
			if i.Sequence != 0 {
				return ErrInDuplicatedField("sequence")
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidSequence
			}
			i.Sequence = binary.LittleEndian.Uint32(kp.Value)
		case InputRequiredTimeLocktime:
			if i.RequiredTimeLocktime != 0 {
				return ErrInDuplicatedField("time locktime")
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidRequiredLocktime
			}
			i.RequiredTimeLocktime = binary.LittleEndian.Uint32(kp.Value)
		case InputRequiredHeightLocktime:
			if i.RequiredHeightLocktime != 0 {
				return ErrInDuplicatedField("height locktime")
			}
			if len(kp.Value) != 4 {
				return ErrInInvalidRequiredHeightLocktime
			}
			i.RequiredHeightLocktime = binary.LittleEndian.Uint32(kp.Value)
		case InputTapKeySig:
			if len(i.TapKeySig) > 0 {
				return ErrInDuplicatedField("taproot key signature")
			}
			if len(kp.Value) != 64 && len(kp.Value) != 65 {
				return ErrInInvalidTapKeySig
			}
			i.TapKeySig = kp.Value
		case InputTapScriptSig:
			if i.TapScriptSig == nil {
				i.TapScriptSig = make([]TapScriptSig, 0)
			}
			if len(kp.Key.KeyData) != 64 {
				return ErrInInvalidTapScriptSigKeyData
			}
			publicKey := kp.Key.KeyData[:32]
			leafHash := kp.Key.KeyData[32:]
			for _, tapScriptSig := range i.TapScriptSig {
				if bytes.Equal(tapScriptSig.PubKey, publicKey) {
					return ErrInDuplicatedField("taproot script signature")
				}
			}
			if len(kp.Value) != 64 && len(kp.Value) != 65 {
				return ErrInInvalidTapScriptSigSignature
			}
			i.TapScriptSig = append(i.TapScriptSig, TapScriptSig{
				PartialSig: PartialSig{
					PubKey:    publicKey,
					Signature: kp.Value,
				},
				LeafHash: leafHash,
			})
		case InputTapLeafScript:
			if i.TapLeafScript == nil {
				i.TapLeafScript = make([]TapLeafScript, 0)
			}
			if (len(kp.Key.KeyData)-1)%32 != 0 {
				return ErrInInvalidTapLeafScriptKeyData
			}
			controlBlock, err := taproot.ParseControlBlock(kp.Key.KeyData)
			if err != nil {
				return ErrInInvalidTapLeafScriptKeyData
			}

			leafVersion := kp.Value[len(kp.Value)-1]
			if uint8(controlBlock.LeafVersion) != uint8(leafVersion) {
				return ErrInInvalidTapLeafScriptVersion
			}

			i.TapLeafScript = append(i.TapLeafScript, TapLeafScript{
				ControlBlock:    *controlBlock,
				TapElementsLeaf: taproot.NewTapElementsLeaf(controlBlock.LeafVersion, kp.Value[:len(kp.Value)-1]),
			})
		case InputTapBip32Derivation:
			if i.TapBip32Derivation == nil {
				i.TapBip32Derivation = make([]TapDerivationPathWithPubKey, 0)
			}
			if len(kp.Key.KeyData) != 33 {
				return ErrInInvalidTapBip32DerivationKeyData
			}
			for _, tapBip32Derivation := range i.TapBip32Derivation {
				if bytes.Equal(tapBip32Derivation.PubKey, kp.Key.KeyData) {
					return ErrInDuplicatedField("taproot bip32 derivation")
				}
			}
			deserializer := bufferutil.NewDeserializer(bytes.NewBuffer(kp.Value))
			nHashes, err := deserializer.ReadVarInt()
			if err != nil {
				return ErrInInvalidTapBip32Derivation
			}
			hashes := make([][]byte, nHashes)
			for i := 0; i < int(nHashes); i++ {
				leafHash, err := deserializer.ReadSlice(32)
				if err != nil {
					return ErrInInvalidTapBip32Derivation
				}
				hashes[i] = leafHash
			}
			bip32Derivation := deserializer.ReadToEnd()
			master, derivationPath, err := readBip32Derivation(bip32Derivation)
			if err != nil {
				return ErrInInvalidTapBip32Derivation
			}
			i.TapBip32Derivation = append(i.TapBip32Derivation, TapDerivationPathWithPubKey{
				DerivationPathWithPubKey: DerivationPathWithPubKey{
					PubKey:               kp.Key.KeyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
				LeafHashes: hashes,
			})
		case InputTapInternalKey:
			if len(i.TapInternalKey) > 0 {
				return ErrInDuplicatedField("taproot internal key")
			}
			if len(kp.Value) != 32 {
				return ErrInInvalidTapInternalKey
			}
			i.TapInternalKey = kp.Value
		case InputTapMerkleRoot:
			if len(i.TapMerkleRoot) > 0 {
				return ErrInDuplicatedField("taproot merkle root")
			}
			if len(kp.Value) != 32 {
				return ErrInInvalidTapMerkleRoot
			}
			i.TapMerkleRoot = kp.Value
		case PsetProprietary:
			pd := ProprietaryData{}
			if err := pd.fromKeyPair(kp); err != nil {
				return err
			}

			if bytes.Equal(pd.Identifier, magicPrefix) {
				switch pd.Subtype {
				case InputIssuanceValue:
					if i.IssuanceValue != 0 {
						return ErrInDuplicatedField("issuance value")
					}
					if len(kp.Value) != 8 {
						return ErrInInvalidIssuanceValue
					}
					i.IssuanceValue = binary.LittleEndian.Uint64(kp.Value)
				case InputIssuanceValueCommitment:
					if len(i.IssuanceValueCommitment) > 0 {
						return ErrInDuplicatedField("issuance value commitment")
					}
					if len(kp.Value) != 33 {
						return ErrInInvalidIssuanceCommitment
					}
					i.IssuanceValueCommitment = kp.Value
				case InputIssuanceValueRangeproof:
					if len(i.IssuanceValueRangeproof) > 0 {
						return ErrInDuplicatedField("issuance value range proof")
					}
					i.IssuanceValueRangeproof = kp.Value
				case InputIssuanceInflationKeysRangeproof:
					if len(i.IssuanceInflationKeysRangeproof) > 0 {
						return ErrInDuplicatedField("issuance inflation keys range proof")
					}
					i.IssuanceInflationKeysRangeproof = kp.Value
				case InputPeginTx:
					if i.PeginTx != nil {
						return ErrInDuplicatedField("pegin tx")
					}
					var tx wire.MsgTx
					buf := bytes.NewReader(kp.Value)
					if err := tx.BtcDecode(
						buf, wire.ProtocolVersion, wire.LatestEncoding,
					); err != nil {
						return ErrInInvalidPeginTx
					}
					i.PeginTx = &tx
				case InputPeginTxoutProof:
					if len(i.PeginTxoutProof) > 0 {
						return ErrInDuplicatedField("pegin txout proof")
					}
					i.PeginTxoutProof = kp.Value
				case InputPeginGenesis:
					if len(i.PeginGenesisHash) > 0 {
						return ErrInDuplicatedField("pegin genesis hash")
					}
					if len(kp.Value) != 32 {
						return ErrInInvalidPeginGenesisHash
					}
					i.PeginGenesisHash = kp.Value
				case InputPeginClaimScript:
					if len(i.PeginClaimScript) > 0 {
						return ErrInDuplicatedField("pegin claim script")
					}
					i.PeginClaimScript = kp.Value
				case InputPeginValue:
					if i.PeginValue != 0 {
						return ErrInDuplicatedField("pegin value")
					}
					if len(kp.Value) != 8 {
						return ErrInInvalidPeginValue
					}
					i.PeginValue = binary.LittleEndian.Uint64(kp.Value)
				case InputPeginWitness:
					if len(i.PeginWitness) > 0 {
						return ErrInDuplicatedField("pegin witness")
					}
					d := bufferutil.NewDeserializer(bytes.NewBuffer(kp.Value))
					witness, err := d.ReadVector()
					if err != nil {
						return ErrInInvalidPeginWitness
					}
					i.PeginWitness = witness
				case InputIssuanceInflationKeys:
					if i.IssuanceInflationKeys != 0 {
						return ErrInDuplicatedField("issuance inflation keys")
					}
					if len(kp.Value) != 8 {
						return ErrInInvalidIssuanceInflationKeys
					}
					i.IssuanceInflationKeys = binary.LittleEndian.Uint64(kp.Value)
				case InputIssuanceInflationKeysCommitment:
					if len(i.IssuanceInflationKeysCommitment) > 0 {
						return ErrInDuplicatedField("issuance inflation keys commitment")
					}
					if len(kp.Value) != 33 {
						return ErrInInvalidIssuanceInflationKeysCommitment
					}
					i.IssuanceInflationKeysCommitment = kp.Value
				case InputIssuanceBlindingNonce:
					if len(i.IssuanceBlindingNonce) > 0 {
						return ErrInDuplicatedField("issuance blinding nonce")
					}
					if len(kp.Value) != 32 {
						return ErrInInvalidIssuanceBlindingNonce
					}
					i.IssuanceBlindingNonce = kp.Value
				case InputIssuanceAssetEntropy:
					if len(i.IssuanceAssetEntropy) > 0 {
						return ErrInDuplicatedField("issuance asset entropy")
					}
					if len(kp.Value) != 32 {
						return ErrInInvalidIssuanceAssetEntropy
					}
					i.IssuanceAssetEntropy = kp.Value
				case InputUtxoRangeProof:
					if len(i.UtxoRangeProof) > 0 {
						return ErrInDuplicatedField("utxo range proof")
					}
					i.UtxoRangeProof = kp.Value
				case InputIssuanceBlindValueProof:
					if len(i.IssuanceBlindValueProof) > 0 {
						return ErrInDuplicatedField("issuance blind value proof")
					}
					i.IssuanceBlindValueProof = kp.Value
				case InputIssuanceBlindInflationKeysProof:
					if len(i.IssuanceBlindInflationKeysProof) > 0 {
						return ErrInDuplicatedField("issuance blind inflation keys proof")
					}
					i.IssuanceBlindInflationKeysProof = kp.Value
				case InputExplicitValue:
					if i.ExplicitValue != 0 {
						return ErrInDuplicatedField("explicit value")
					}
					if len(kp.Value) != 8 {
						return ErrInInvalidExplicitValue
					}
					i.ExplicitValue = binary.LittleEndian.Uint64(kp.Value)
				case InputValueProof:
					if len(i.ValueProof) > 0 {
						return ErrInDuplicatedField("value proof")
					}
					i.ValueProof = kp.Value
				case InputExplicitAsset:
					if len(i.ExplicitAsset) > 0 {
						return ErrInDuplicatedField("explicit asset")
					}
					if len(kp.Value) != 32 {
						return ErrInInvalidExplicitAsset
					}
					i.ExplicitAsset = kp.Value
				case InputAssetProof:
					if len(i.AssetProof) > 0 {
						return ErrInDuplicatedField("asset proof")
					}
					i.AssetProof = kp.Value
				case InputBlindedIssuanceValue:
					if i.BlindedIssuance != nil {
						return ErrInDuplicatedField("blinded issuance flag")
					}
					if len(kp.Value) != 1 {
						return ErrInInvalidBlindedIssuanceValue
					}
					b := kp.Value[0] == 1
					i.BlindedIssuance = &b
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

func (i *Input) isTaproot() bool {
	return len(i.TapKeySig) > 0 ||
		len(i.TapInternalKey) > 0 ||
		len(i.TapMerkleRoot) > 0 ||
		len(i.TapLeafScript) > 0 ||
		len(i.TapScriptSig) > 0
}
