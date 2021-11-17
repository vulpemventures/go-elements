package psetv2

import (
	"errors"

	"github.com/vulpemventures/go-elements/elementsutil"

	"github.com/vulpemventures/go-elements/transaction"
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
	PsetElementsOutValueCommitment      = 0x01
	PsetElementsOutAsset                = 0x02
	PsetElementsOutAssetCommitment      = 0x03
	PsetElementsOutValueRangeproof      = 0x04
	PsetElementsOutAssetSurjectionProof = 0x05
	PsetElementsOutBlindingPubkey       = 0x06
	PsetElementsOutEcdhPubkey           = 0x07
	PsetElementsOutBlinderIndex         = 0x08
	PsetElementsOutBlindValueProof      = 0x09
	PsetElementsOutBlindAssetProof      = 0x0a
)

var (
	ErrMissingOutAsset                 = errors.New("missing output asset")
	ErrMissingOutAmount                = errors.New("missing output amount")
	ErrMissingScript                   = errors.New("missing output script")
	ErrInvalidValueCommitmentLength    = errors.New("invalid value commitment length")
	ErrInvalidOutAssetLength           = errors.New("invalid output asset length")
	ErrInvalidOutAssetCommitmentLength = errors.New("invalid output asset commitment length")
	ErrInvalidOutputScriptLength       = errors.New("invalid output script length")
)

type Output struct {
	// The redeem script for this output.
	redeemScript []byte
	// The witness script for this output.
	witnessScript []byte
	// A map from public keys needed to spend this output to their
	// corresponding master key fingerprints and derivation paths.
	bip32Derivation []DerivationPathWithPubKey
	// (PSET2) The amount of the output
	outputAmount *int64
	// (PSET2) The output script
	outputScript []byte
	// The 33 byte Value Commitment for this output.
	outputValueCommitment []byte
	// The explicit 32 byte asset tag for this output.
	outputAsset []byte
	// The 33 byte Asset Commitment
	outputAssetCommitment []byte
	// The rangeproof for the value of this output.
	outputValueRangeproof []byte
	// The asset surjection proof for this output's asset.
	outputAssetSurjectionProof []byte
	// The 33 byte blinding pubkey to be used when blinding this output.
	outputBlindingPubkey []byte
	// The 33 byte ephemeral pubkey used for ECDH in the blinding of this output
	outputEcdhPubkey []byte
	// Index of the input whose owner should blind this output.
	outputBlinderIndex *uint32
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

func (o *Output) IsBlinded() bool {
	return o.outputValueCommitment != nil &&
		o.outputAssetCommitment != nil &&
		o.outputValueRangeproof != nil &&
		o.outputAssetSurjectionProof != nil &&
		o.outputEcdhPubkey != nil &&
		o.outputBlindingPubkey != nil
}

func (o *Output) ToBlind() bool {
	return o.outputBlindingPubkey != nil && o.outputBlinderIndex != nil
}

func psetOutputFromTxOutput(output transaction.TxOutput) (*Output, error) {
	script := output.Script

	var outputAmount *int64
	var outputCommitment []byte
	if len(output.Value) == 9 && output.Value[0] == 1 {
		o, err := elementsutil.ElementsToSatoshiValue(output.Value)
		if err != nil {
			return nil, err
		}
		ov := int64(o)
		outputAmount = &ov
	} else {
		if len(output.Value) != 33 {
			return nil, ErrInvalidAssetCommitmentLength
		}

		outputCommitment = output.Value
	}

	var outputAsset []byte
	var outputAssetCommitment []byte
	if isAssetExplicit(output.Asset) {
		outputAsset = output.Asset
	} else {
		if len(output.Value) != 33 {
			return nil, ErrInvalidAssetCommitmentLength
		}

		outputAssetCommitment = output.Asset
	}

	var outputBlindingPubkey []byte
	if len(output.Nonce) == 33 && (output.Nonce[0] == 2 || output.Nonce[0] == 3) {
		outputBlindingPubkey = output.Nonce
	}

	return &Output{
		outputScript:          script,
		outputAmount:          outputAmount,
		outputValueCommitment: outputCommitment,
		outputAsset:           outputAsset,
		outputAssetCommitment: outputAssetCommitment,
		outputBlindingPubkey:  outputBlindingPubkey,
	}, nil
}
