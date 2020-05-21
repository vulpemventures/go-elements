package payment_test

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
)

const (
	privateKeyHex = "1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d"
)

var privateKeyBytes, _ = hex.DecodeString(privateKeyHex)

//This examples shows how standard P2PKH address can be created
func ExampleFromPublicKey() {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)
	pay := payment.FromPublicKey(publicKey, &network.Regtest)
	fmt.Printf("P2PKH address %v\n:", pay.PubKeyHash())
}

//This examples shows how nested payment can be done in order to create non native SegWit(P2SH-P2WPKH) address
func ExampleFromPayment() {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)
	p2wpkh := payment.FromPublicKey(publicKey, &network.Regtest)
	pay, err := payment.FromPayment(p2wpkh)
	p2sh, err := pay.ScriptHash()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Non native SegWit address %v\n:", p2sh)
}
