package psetv2

import "bytes"

const (
	//Per output types: BIP 174, 370, 371
	PsbtGlobalUnsignedTx          = 0x00 //BIP 174
	PsbtGlobalXpub                = 0x01 //BIP 174
	PsbtGlobalTxVersion           = 0x02 //BIP 370
	PsbtGlobalFallbackLocktime    = 0x03 //BIP 370
	PsbtGlobalInputCount          = 0x04 //BIP 370
	PsbtGlobalOutputCount         = 0x05 //BIP 370
	PsbtGlobalTxModifiable        = 0x06 //BIP 370
	PsbtGlobalSighashSingleInputs = 0x07 //BIP 370
	PsbtGlobalVersion             = 0xFB //BIP 174
	PsbtGlobalProprietary         = 0xFC //BIP 174

	//Elements Proprietary types
	PsbtElementsGlobalScalar       = 0x00
	PsbtElementsGlobalTxModifiable = 0x01
)

type Global struct {
	// global transaction data
	txInfo TxInfo
	// the version number of this PSET. Must be present.
	version uint32
	// a global map from extended public keys to the used key fingerprint and
	// derivation path as defined by BIP 32
	xPub DerivationPathInfo
	// scalars used for blinding
	scalars [32]byte
	// elements tx modifiable flag
	elementsTxModifiableFlag uint8
	// other proprietary fields
	proprietary []proprietaryData
	// unknown global key-value pairs.
	unknown []keyPair
}

// TxInfo represents global information about the transaction
type TxInfo struct {
	// Transaction version. Must be 2.
	version uint32
	// Locktime to use if no inputs specify a minimum locktime to use.
	// May be omitted in which case it is interpreted as 0.
	fallBackLockTime uint32
	// Number of inputs in the transaction
	// Not public. Users should not be able to mutate this directly
	// This will be automatically whenever pset inputs are added
	inputCount int
	// Number of outputs in the transaction
	// Not public. Users should not be able to mutate this directly
	// This will be automatically whenever pset inputs are added
	outputCount int
	// Flags indicating that the transaction may be modified.
	// May be omitted in which case it is interpreted as 0.
	txModifiable byte
}

// DerivationPathInfo global information about xpub keypair
type DerivationPathInfo struct {
	// extendedPubKey extended public key as defined by BIP 32
	extendedPubKey [78]byte
	//masterKeyFingerPrint master key fingerprint as defined by BIP 32
	masterKeyFingerPrint [4]byte
	// derivationPath derivation path of the public key
	derivationPath uint32
}

func deserializeGlobal(buf *bytes.Buffer) (*Global, error) {
	return nil, nil
}
