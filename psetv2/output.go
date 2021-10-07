package psetv2

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	//Per output types: BIP 174, 370, 371
	PsbtOutRedeemScript       = 0x00 //BIP 174
	PsbtOutWitnessScript      = 0x01 //BIP 174
	PsbtOutBip32Derivation    = 0x02 //BIP 174
	PsbtOutAmount             = 0x03 //BIP 370
	PsbtOutScript             = 0x04 //BIP 370
	PsbtOutTapInternalKey     = 0x05 //BIP 371
	PsbtOutTapTree            = 0x06 //BIP 371
	PsbtOutTapLeafScript      = 0x06 //BIP 371 //TODO is duplicate key type allowed?
	PsbtOutTapBip32Derivation = 0x07 //BIP 371
	PsbtOutProprietary        = 0xFC //BIP 174

	//Elements Proprietary types
	PsbtElementsOutValueCommitment      = 0x01
	PsbtElementsOutAsset                = 0x02
	PsbtElementsOutAssetCommitment      = 0x03
	PsbtElementsOutValueRangeproof      = 0x04
	PsbtElementsOutAssetSurjectionProof = 0x05
	PsbtElementsOutBlindingPubkey       = 0x06
	PsbtElementsOutEcdhPubkey           = 0x07
	PsbtElementsOutBlinderIndex         = 0x08
	PsbtElementsOutBlindValueProof      = 0x09
	PsbtElementsOutBlindAssetProof      = 0x0a
)

var (
	ErrMissingOutAsset  = errors.New("missing output asset")
	ErrMissingOutAmount = errors.New("missing output amount")
	ErrMissingScript    = errors.New("missing output script")
)

type Output struct {
	// The redeem script for this output.
	redeemScript []byte
	// The witness script for this output.
	witnessScript []byte
	// A map from public keys needed to spend this output to their
	// corresponding master key fingerprints and derivation paths.
	bip32Derivation []*Bip32Derivation
	// (PSET2) The amount of the output
	outputAmount int64
	// (PSET2) The output script
	outputScript []byte
	// The 33 byte Value Commitment for this output.
	outputValueCommitment [33]byte
	// The explicit 32 byte asset tag for this output.
	outputAsset [32]byte
	// The 33 byte Asset Commitment
	outputAssetCommitment [33]byte
	// The rangeproof for the value of this output.
	outputValueRangeproof []byte
	// The asset surjection proof for this output's asset.
	outputAssetSurjectionProof []byte
	// The 33 byte blinding pubkey to be used when blinding this output.
	outputBlindingPubkey []byte
	// The 33 byte ephemeral pubkey used for ECDH in the blinding of this output
	outputEcdhPubkey []byte
	// Index of the input whose owner should blind this output.
	outputBlinderIndex uint32
	// An explicit value rangeproof that proves that the value commitment in
	//PSBT_ELEMENTS_OUT_VALUE_COMMITMENT matches the explicit value in PSBT_OUT_VALUE
	outputBlindValueProof []byte
	// An asset surjection proof with this output's asset as the only asset in
	//the input set in order to prove that the asset commitment in
	//PSBT_ELEMENTS_OUT_ASSET_COMMITMENT matches the explicit asset in PSBT_ELEMENTS_OUT_ASSET
	outputBlindAssetProof []byte
	proprietaryData       []proprietaryData
	// Unknown key-value pairs for this input.
	unknowns []keyPair
}

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
				&Bip32Derivation{
					PubKey:               kp.key.keyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)
		case PsbtOutAmount:
			output.outputAmount = int64(binary.LittleEndian.Uint64(kp.value))
			outputAmountFound = true
		case PsbtOutScript:
			output.outputScript = kp.value
			outputScriptFound = true
		case PsbtGlobalProprietary:
			pd := &proprietaryData{}
			if err := pd.proprietaryDataFromKeyPair(*kp); err != nil {
				return nil, err
			}

			if bytes.Equal(pd.identifier, psetMagic[:len(psetMagic)-1]) {
				switch pd.subtype {
				case PsbtElementsOutValueCommitment:
					var outValueCommitment [33]byte
					copy(outValueCommitment[:], kp.value[:])
					output.outputValueCommitment = outValueCommitment
				case PsbtElementsOutAsset:
					var outputAsset [32]byte
					copy(outputAsset[:], kp.value[:])
					output.outputAsset = outputAsset
					outputAssetFound = true
				case PsbtElementsOutAssetCommitment:
					var outputAssetCommitment [33]byte
					copy(outputAssetCommitment[:], kp.value[:])
					output.outputAssetCommitment = outputAssetCommitment
				case PsbtElementsOutValueRangeproof:
					output.outputValueRangeproof = kp.value
				case PsbtElementsOutAssetSurjectionProof:
					output.outputAssetSurjectionProof = kp.value
				case PsbtElementsOutBlindingPubkey:
					if !validatePubkey(kp.value) {
						return nil, ErrInvalidPsbtFormat
					}

					output.outputBlindingPubkey = kp.value
				case PsbtElementsOutEcdhPubkey:
					if !validatePubkey(kp.value) {
						return nil, ErrInvalidPsbtFormat
					}

					output.outputEcdhPubkey = kp.value
				case PsbtElementsOutBlinderIndex:
					output.outputBlinderIndex = binary.LittleEndian.Uint32(kp.value)
				case PsbtElementsOutBlindValueProof:
					output.outputBlindValueProof = kp.value
				case PsbtElementsOutBlindAssetProof:
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
