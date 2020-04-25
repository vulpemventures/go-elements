package main

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
)

func randomKey() (string, error) {
	ecPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return "", err
	}
	privateKeyBytes := ecPrivateKey.Serialize()
	return hex.EncodeToString(privateKeyBytes), nil
}

func main() {
	privKeyHex := "1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d"
	privateKeyBytes, _ := hex.DecodeString(privKeyHex)
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)

	pay := payment.FromPublicKey(publicKey, &network.Regtest)
	println(pay.PubKeyHash())
	println(pay.WitnessPubKeyHash())

}
