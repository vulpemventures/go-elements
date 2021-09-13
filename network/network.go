package network

// Network type represents prefixes for each network
// https://en.bitcoin.it/wiki/List_of_address_prefixes
type Network struct {
	Name string
	// Human-readable part for Bech32 encoded segwit addresses, as defined
	// in BIP 173.
	Bech32 string
	// Human-readable part for Blech32 encoded segwit confidential addresses,
	// as defined in BIP 173.
	Blech32 string
	// BIP32 hierarchical deterministic extended key magics
	HDPublicKey  [4]byte
	HDPrivateKey [4]byte
	// Address encoding magic
	PubKeyHash byte
	ScriptHash byte
	// First byte of a WIF private key
	Wif byte
	// Confidential prefix
	Confidential byte
	// Bitcoin Asset Hash for the current network
	AssetID string
	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32
}

// Liquid defines the network parameters for the main Liquid network.
var Liquid = Network{
	Name:         "liquid",
	Bech32:       "ex",
	Blech32:      "lq",
	HDPublicKey:  [4]byte{0x04, 0x88, 0xb2, 0x1e},
	HDPrivateKey: [4]byte{0x04, 0x88, 0xad, 0xe4},
	PubKeyHash:   57,
	ScriptHash:   39,
	Wif:          0x80,
	Confidential: 12,
	AssetID:      "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
	HDCoinType:   1776,
}

// Regtest defines the network parameters for the regression test network.
var Regtest = Network{
	Name:         "regtest",
	Bech32:       "ert",
	Blech32:      "el",
	HDPublicKey:  [4]byte{0x04, 0x35, 0x87, 0xcf},
	HDPrivateKey: [4]byte{0x04, 0x35, 0x83, 0x94},
	PubKeyHash:   235,
	ScriptHash:   75,
	Wif:          0xef,
	Confidential: 4,
	AssetID:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	HDCoinType:   1,
}
