package payment_test

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"testing"
)

const (
	privKeyHex1 = "1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d"
	privKeyHex2 = "4d6718d4a02f774e752faa97e2c3b70db6b9d9ed5bd2fcecb093bd650f449a51"
)

var privateKeyBytes1, _ = hex.DecodeString(privKeyHex1)
var privateKeyBytes2, _ = hex.DecodeString(privKeyHex2)

func TestLegacyAddress(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes1)

	pay := payment.FromPublicKey(publicKey, &network.Regtest, nil)
	if pay.PubKeyHash() != "2dxEMfPLNa6rZRAfPe7wNWoaUptyBzQ2Zva" {
		t.Errorf("TestLegacyAddress: error when encoding legacy")
	}
}

func TestSegwitAddress(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes1)

	pay := payment.FromPublicKey(publicKey, &network.Regtest, nil)
	p2pkh, err := pay.WitnessPubKeyHash()
	if err != nil {
		t.Error(err)
	}
	if p2pkh != "ert1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5kjfrrt" {
		t.Errorf("TestSegwitAddress: error when encoding segwit")
	}
}

func TestScriptHash(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes1)
	p2wpkh := payment.FromPublicKey(publicKey, &network.Regtest, nil)
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

	p2ms, err := payment.FromScript(redeemScriptBytes, &network.Regtest, nil)
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

func TestFromPublicKeys(t *testing.T) {
	_, publicKey1 := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes1)
	_, publicKey2 := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes2)

	p2ms, err := payment.FromPublicKeys(
		[]*btcec.PublicKey{publicKey1, publicKey2},
		1,
		&network.Regtest,
		nil,
	)
	if err != nil {
		t.Error(err)
	}

	if hex.EncodeToString(p2ms.Script) != "5121036f5646ed688b9279369da0a4ad78953ae7e6d300436ca8a3264360efe38236e321023c61f59e9a3a3eb01c3ed0cf967ad217153944bcf2498a8fd6e70b27c7ab6ee652ae" {
		t.Error("hex value of p2ms script not as expected")
	}

	p2wsh, err := payment.FromPayment(p2ms)
	if err != nil {
		t.Error(err)
	}

	p2wshAddress, err := p2wsh.WitnessScriptHash()
	if err != nil {
		t.Error(err)
	}
	if p2wshAddress != "ert1q484pt3gqgthcxa35nl4t6utpd0uf7tkm240hlxe6k4newkydwcqs5sjc4c" {
		t.Errorf("TestSegwitAddress: error when encoding segwit")
	}

	pay, err := payment.FromPayment(p2ms)
	p2sh, err := pay.ScriptHash()
	if err != nil {
		t.Error(err)
	}
	if p2sh != "XJkohBHRMT8JUknSqCH7aJP9gAuAe9eNLY" {
		t.Errorf("TestScriptHash: error when encoding script hash")
	}
}

func TestPaymentConfidentialPubKeyHash(t *testing.T) {
	expected := "VTpzxkqVGbraaCz18fQ2GxLvZkupCi2MPtUdt9ygAEeZ8v9gZPtkD5RUc" +
		"ap55WZ3aVsbUG6TsQvXc8R3"
	pk1 := "030000000000000000000000000000000000000000000000000000000000000001"
	pk1Byte, err := hex.DecodeString(pk1)
	if err != nil {
		t.Fatal(err)
	}
	pubKey1, err := btcec.ParsePubKey(pk1Byte, btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	pk2 := "030000000000000000000000000000000000000000000000000000000000000001"
	pk2Byte, err := hex.DecodeString(pk2)
	if err != nil {
		t.Fatal(err)
	}
	pubKey2, err := btcec.ParsePubKey(pk2Byte, btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	payment := payment.FromPublicKey(pubKey1, &network.Liquid, pubKey2)
	assert.Equal(t, expected, payment.ConfidentialPubKeyHash())
}

func TestPaymentConfidentialScriptHash(t *testing.T) {
	expected := "VJLCUu2hpcjPaTGMnANXni8wVYjsCAiTEznE5zgRZZyAWXE2P6rz6Dvph" +
		"BHSn7iz4w9sLb3mFSHGJbte"
	scriptHash, err := hex.DecodeString(
		"9f840a5fc02407ef0ad499c2ec0eb0b942fb0086")
	if err != nil {
		t.Fatal(err)
	}

	script := append(append([]byte{txscript.OP_HASH160, 0x14}, scriptHash...),
		[]byte{txscript.OP_EQUAL}...)

	pk1 := "030000000000000000000000000000000000000000000000000000000000000001"
	pk2Byte, err := hex.DecodeString(pk1)
	if err != nil {
		t.Fatal(err)
	}
	blindingKey, err := btcec.ParsePubKey(pk2Byte, btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	payment, err := payment.FromScript(script, &network.Liquid, blindingKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, payment.ConfidentialScriptHash())

}

func TestPaymentConfidentialWitnessPubKeyHash(t *testing.T) {
	expected := "lq1qqvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz95" +
		"tny4ul3zq2qcskw55h5rhzymdpv5dzw6hr8jz3tq5y"
	pk1 := "030000000000000000000000000000000000000000000000000000000000000001"
	pk1Byte, err := hex.DecodeString(pk1)
	if err != nil {
		t.Fatal(err)
	}
	pubKey1, err := btcec.ParsePubKey(pk1Byte, btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	pk2 := "030000000000000000000000000000000000000000000000000000000000000001"
	pk2Byte, err := hex.DecodeString(pk2)
	if err != nil {
		t.Fatal(err)
	}
	pubKey2, err := btcec.ParsePubKey(pk2Byte, btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	payment := payment.FromPublicKey(pubKey1, &network.Liquid, pubKey2)
	address, err := payment.ConfidentialWitnessPubKeyHash()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, address)
}

func TestConfidentialWitnessScriptHash(t *testing.T) {
	expected := "lq1qqvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
		"r5x3lrzmrq2mc3c6aa85wgxxfm9v8r062qwq4ty579p54pn2q2hq6f9r3gz0h4tn"

	scriptHash, err := hex.DecodeString(
		"d0d1f8c5b1815bc471aef4f4720c64ecac38dfa501c0aac94f1434a866a02ae0")
	if err != nil {
		t.Fatal(err)
	}

	script := append([]byte{txscript.OP_0, 0x14}, scriptHash...)

	pk1 := "030000000000000000000000000000000000000000000000000000000000000001"
	pk2Byte, err := hex.DecodeString(pk1)
	if err != nil {
		t.Fatal(err)
	}
	blindingKey, err := btcec.ParsePubKey(pk2Byte, btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	p, err := payment.FromScript(script, &network.Liquid, blindingKey)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := p.ConfidentialWitnessScriptHash()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, addr)
}
