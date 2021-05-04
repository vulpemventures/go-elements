package pegin

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcd/txscript"

	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/vulpemventures/go-elements/address"

	"github.com/btcsuite/btcd/btcec"
)

const (
	MainNet NetworkType = iota
	RegtestNet
)

type NetworkType int

type AddressInfo struct {
	ClaimScript      string
	MainChainAddress string
}

func PeginAddress(
	contract []byte,
	btcNetwork *chaincfg.Params,
	isDynaFedEnabled bool,
	fedpegScript []byte,
) (string, error) {
	pops, err := address.ParseScript(fedpegScript)
	if err != nil {
		return "", err
	}

	var mainChainAddress string
	if isDynaFedEnabled || address.IsScriptHash(pops) {
		//P2SH - P2WSH(P2CH)
		witnessScriptHash := sha256.Sum256(contract)
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_0).AddData(witnessScriptHash[:])
		script, err := builder.Script()
		if err != nil {
			return "", err
		}
		ps2h, err := btcutil.NewAddressScriptHash(script, btcNetwork)
		if err != nil {
			return "", err
		}
		mainChainAddress = ps2h.String()
	} else {
		//P2WSH - P2CH
		witnessScriptHash := sha256.Sum256(contract)
		p2wsh, err := btcutil.NewAddressWitnessScriptHash(
			witnessScriptHash[:],
			btcNetwork,
		)
		if err != nil {
			return "", err
		}
		mainChainAddress = p2wsh.String()
	}

	return mainChainAddress, nil
}

func ClaimWitnessScript(
	publicKeyBytes []byte,
	net *network.Network,
) (string, error) {

	publicKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return "", err
	}

	p2wpkh := payment.FromPublicKey(
		publicKey,
		net,
		nil,
	)
	return hex.EncodeToString(p2wpkh.WitnessScript), nil
}

func getNetworkParams(
	networkType NetworkType,
) (*network.Network, *chaincfg.Params) {
	var liquidNetwork *network.Network
	var btcNetwork *chaincfg.Params
	switch networkType {
	case MainNet:
		liquidNetwork = &network.Liquid
		btcNetwork = &chaincfg.MainNetParams
	case RegtestNet:
		liquidNetwork = &network.Regtest
		btcNetwork = &chaincfg.RegressionNetParams
	}

	return liquidNetwork, btcNetwork
}

type FedpegInfo struct {
	FedpegScript  []byte
	FedpegProgram []byte
}

// TODO - get fedpeg details from live blockchain
func GetFedpegInfo() (*FedpegInfo, error) {
	return &FedpegInfo{}, nil
}
