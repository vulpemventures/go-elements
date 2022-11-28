package payment_test

import (
	"encoding/hex"
	"testing"

	"github.com/louisinger/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
)

const (
	privKeyHex1 = "1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d"
	privKeyHex2 = "4d6718d4a02f774e752faa97e2c3b70db6b9d9ed5bd2fcecb093bd650f449a51"
)

var privateKeyBytes1, _ = hex.DecodeString(privKeyHex1)
var privateKeyBytes2, _ = hex.DecodeString(privKeyHex2)

func TestLegacyPubkeyHash(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(privateKeyBytes1)

	pay := payment.FromPublicKey(publicKey, &network.Regtest, nil)
	addr, err := pay.PubKeyHash()
	if err != nil {
		t.Fatal(err)
	}
	expected := "2dxEMfPLNa6rZRAfPe7wNWoaUptyBzQ2Zva"
	assert.Equal(t, expected, addr)
}

func TestSegwitPubkeyHash(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(privateKeyBytes1)

	pay := payment.FromPublicKey(publicKey, &network.Regtest, nil)
	addr, err := pay.WitnessPubKeyHash()
	if err != nil {
		t.Error(err)
	}
	expected := "ert1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5kjfrrt"
	assert.Equal(t, expected, addr)
}

func TestLegacyScriptHash(t *testing.T) {
	_, publicKey := btcec.PrivKeyFromBytes(privateKeyBytes1)
	p2wpkh := payment.FromPublicKey(publicKey, &network.Regtest, nil)

	p2sh, err := payment.FromPayment(p2wpkh)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := p2sh.ScriptHash()
	if err != nil {
		t.Error(err)
	}
	expectedAddr := "XZavBojABpfXhPWkw7y9YYFNAezUHZR47m"
	assert.Equal(t, expectedAddr, addr)
}

func TestSegwitScriptHash(t *testing.T) {
	redeemScript := "52410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959" +
		"f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d0" +
		"8ffb10d4b84104c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09" +
		"b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950" +
		"cfe52a52ae"
	redeemScriptBytes, err := hex.DecodeString(redeemScript)
	if err != nil {
		t.Error(err)
	}

	p2ms, err := payment.FromScript(
		redeemScriptBytes,
		&network.Regtest,
		nil,
	)
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
	if p2wshAddress != "ert1q2z45rh444qmeand48lq0wp3jatxs2nzh"+
		"492ds9s5yscv2pplxwesajz7q3" {
		t.Errorf("TestSegwitAddress: error when encoding segwit")
	}
}

func TestMultisig(t *testing.T) {
	_, publicKey1 := btcec.PrivKeyFromBytes(privateKeyBytes1)
	_, publicKey2 := btcec.PrivKeyFromBytes(privateKeyBytes2)

	p2ms, err := payment.FromPublicKeys(
		[]*btcec.PublicKey{publicKey1, publicKey2},
		2,
		&network.Regtest,
		nil,
	)
	if err != nil {
		t.Error(err)
	}

	expectedRedeemScript := "5221036f5646ed688b9279369da0a4ad78953ae7e6d300436" +
		"ca8a3264360efe38236e321023c61f59e9a3a3eb01c3ed0cf967ad217153944bcf2498a" +
		"8fd6e70b27c7ab6ee652ae"
	assert.Equal(t, expectedRedeemScript, hex.EncodeToString(p2ms.Redeem.Script))

	p2wshAddr, err := p2ms.WitnessScriptHash()
	if err != nil {
		t.Error(err)
	}
	expectedAddr :=
		"ert1q3pa0pn2zef7eh2wuj4nqzas3xfzap79dful920kv6fuey592ujvs274fsu"
	assert.Equal(t, expectedAddr, p2wshAddr)

	p2shAddr, err := p2ms.ScriptHash()
	if err != nil {
		t.Error(err)
	}
	expectedAddr = "XLggw3oXkn4QwAkNt5uG8EBKTuGf69BJJG"
	assert.Equal(t, expectedAddr, p2shAddr)
}

func TestLegacyPubKeyHashConfidential(t *testing.T) {
	pubkeyBytes, _ := hex.DecodeString(
		"030000000000000000000000000000000000000000000000000000000000000001",
	)
	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	pay := payment.FromPublicKey(pubkey, &network.Liquid, pubkey)
	address, err := pay.ConfidentialPubKeyHash()
	if err != nil {
		t.Fatal(err)
	}
	expected := "VTpzxkqVGbraaCz18fQ2GxLvZkupCi2MPtUdt9ygAEeZ8v9gZPtkD5RUcap55" +
		"WZ3aVsbUG6TsQvXc8R3"
	assert.Equal(t, expected, address)
}

func TestLegacyScriptHashConfidential(t *testing.T) {
	script, _ := hex.DecodeString(
		"a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687",
	)
	pubkeyBytes, _ := hex.DecodeString(
		"030000000000000000000000000000000000000000000000000000000000000001",
	)
	blindingKey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	pay, err := payment.FromScript(script, &network.Liquid, blindingKey)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := pay.ConfidentialScriptHash()
	if err != nil {
		t.Fatal(err)
	}
	expected := "VJLCUu2hpcjPaTGMnANXni8wVYjsCAiTEznE5zgRZZyAWXE2P6rz6DvphBHSn" +
		"7iz4w9sLb3mFSHGJbte"
	assert.Equal(t, expected, addr)
}

func TestSegwitPubKeyHashConfidential(t *testing.T) {
	pubkeyBytes, _ := hex.DecodeString("030000000000000000000000000000000000000000000000000000000000000001")
	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	pay := payment.FromPublicKey(pubkey, &network.Liquid, pubkey)
	address, err := pay.ConfidentialWitnessPubKeyHash()
	if err != nil {
		t.Fatal(err)
	}

	expected := "lq1qqvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz95tn" +
		"y4ul3zq2qcskw55h5rhzymdpv5dzw6hr8jz3tq5y"
	assert.Equal(t, expected, address)
}

func TestSegwitScriptHashConfidential(t *testing.T) {
	script, _ := hex.DecodeString(
		"0014d0d1f8c5b1815bc471aef4f4720c64ecac38dfa501c0aac94f1434a866a02ae0",
	)
	pubkeyBytes, _ := hex.DecodeString(
		"030000000000000000000000000000000000000000000000000000000000000001",
	)
	blindingKey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	pay, err := payment.FromScript(script, &network.Liquid, blindingKey)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := pay.ConfidentialWitnessScriptHash()
	if err != nil {
		t.Fatal(err)
	}

	expected := "lq1qqvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5x3l" +
		"rzmrq2mc3c6aa85wgxxfm9v8r062qwq4ty579p54pn2q2hq6f9r3gz0h4tn"
	assert.Equal(t, expected, addr)
}
