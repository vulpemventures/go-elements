package psetv2

import "bytes"

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

type Output struct {
}

func deserializeOutputs(buf *bytes.Buffer) ([]Output, error) {
	return nil, nil
}
