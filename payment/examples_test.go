package payment_test

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
)

const (
	privateKeyHex = "1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d"
)

var privateKeyBytes, _ = hex.DecodeString(privateKeyHex)

//This examples shows how standard P2PKH address can be created
func ExampleFromPublicKey() {
	_, publicKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	pay := payment.FromPublicKey(publicKey, &network.Regtest, nil)
	addr, _ := pay.PubKeyHash()
	fmt.Printf("P2PKH address %v\n:", addr)
}

//This examples shows how nested payment can be done in order to create non native SegWit(P2SH-P2WPKH) address
func ExampleFromPayment() {
	_, publicKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	p2wpkh := payment.FromPublicKey(publicKey, &network.Regtest, nil)
	pay, err := payment.FromPayment(p2wpkh)
	p2sh, err := pay.ScriptHash()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Non native SegWit address %v\n:", p2sh)
}

func ExampleConfidentialWitnessPubKeyHash() {
	pk, err := btcec.NewPrivateKey()
	if err != nil {
		fmt.Println(err)
	}
	blindingKey := pk.PubKey()

	privkey, err := btcec.NewPrivateKey()
	if err != nil {
		fmt.Println(err)
	}

	p2wpkh := payment.FromPublicKey(privkey.PubKey(), &network.Regtest, blindingKey)
	confidentialWpkh, err := p2wpkh.ConfidentialWitnessPubKeyHash()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Confidential SegWit address %v\n:", confidentialWpkh)
}
