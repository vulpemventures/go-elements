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
	p2pkh, err := pay.WitnessPubKeyHash()
	if err != nil {
		t.Error(err)
	}
	if p2pkh != "ert1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5kjfrrt" {
		t.Errorf("TestSegwitAddress: error when encoding segwit")
	}
}

func TestScriptHash(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)
	p2wpkh := payment.FromPublicKey(publicKey, &network.Regtest)
	pay, err := payment.FromPayment(p2wpkh)
	p2sh, err := pay.ScriptHash()
	if err != nil {
		t.Error(err)
	}
	if p2sh != "XZavBojABpfXhPWkw7y9YYFNAezUHZR47m" {
		t.Errorf("TestScriptHash: error when encoding script hash")
	}
}

func TestP2WSH(t *testing.T) {
	redeemScript := "52410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b84104c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a52ae"
	redeemScriptBytes, err := hex.DecodeString(redeemScript)
	if err != nil {
		t.Error(err)
	}

	p2ms, err := payment.FromScript(redeemScriptBytes, &network.Regtest)
	if err != nil {
		t.Error(err)
	}

	p2wsh, err := payment.FromPayment(p2ms)
	if err != nil {
		t.Error(err)
	}

	p2wshAddress, err := p2wsh.WitnessScriptHash()
	if err != nil {
		t.Error(err)
	}
	if p2wshAddress != "ert1q2z45rh444qmeand48lq0wp3jatxs2nzh492ds9s5yscv2pplxwesajz7q3" {
		t.Errorf("TestSegwitAddress: error when encoding segwit")
	}
}
