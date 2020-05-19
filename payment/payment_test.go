package payment_test

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"testing"
)

const privKeyHex = "1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d"

var privateKeyBytes, _ = hex.DecodeString(privKeyHex)

func TestLegacyAddress(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)

	pay := payment.FromPublicKey(publicKey, &network.Regtest)
	if pay.PubKeyHash() != "2dxEMfPLNa6rZRAfPe7wNWoaUptyBzQ2Zva" {
		t.Errorf("TestLegacyAddress: error when encoding legacy")
	}
}

func TestSegwitAddress(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)

	pay := payment.FromPublicKey(publicKey, &network.Regtest)
	if pay.WitnessPubKeyHash() != "ert1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5kjfrrt" {
		t.Errorf("TestSegwitAddress: error when encoding segwit")
	}
}

func TestP2WSH(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)
	pay := payment.FromPublicKey(publicKey, &network.Regtest)
	if pay.WitnessScriptHash() != "ert1q5kvuxm0d64ecvmh2kklku6afw03g849af8jfac3t6vgjwrar8xsseary2s" {
		t.Errorf("TestSegwitAddress: error when encoding segwit")
	}
}
