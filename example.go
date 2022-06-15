package main

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
)

func randomKey() (string, error) {
	ecPrivateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	privateKeyBytes := ecPrivateKey.Serialize()
	return hex.EncodeToString(privateKeyBytes), nil
}

func main() {
	privKeyHex := "1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d"
	privateKeyBytes, _ := hex.DecodeString(privKeyHex)
	_, publicKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	pay := payment.FromPublicKey(publicKey, &network.Regtest, nil)
	legacyAddress, _ := pay.PubKeyHash()
	segwitAddress, _ := pay.WitnessPubKeyHash()
	println(legacyAddress)
	println(segwitAddress)

}
