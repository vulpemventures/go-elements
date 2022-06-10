package payment_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/taproot"
)

func randomTapscriptTree() *taproot.IndexedElementsTapScriptTree {
	tapScriptLeaves := make([]taproot.TapElementsLeaf, 4)
	for i := 0; i < len(tapScriptLeaves); i++ {
		numLeafBytes := rand.Intn(1000)
		scriptBytes := make([]byte, numLeafBytes)
		if _, err := rand.Read(scriptBytes[:]); err != nil {
			panic(err)
		}
		tapScriptLeaves[i] = taproot.NewBaseTapElementsLeaf(scriptBytes)
	}

	return taproot.AssembleTaprootScriptTree(tapScriptLeaves...)

}

var testTree = randomTapscriptTree()
var rootHash = testTree.RootNode.TapHash()
var internalKey, _ = btcec.NewPrivateKey()
var blindingKey, _ = btcec.NewPrivateKey()

var tweakedKey = taproot.ComputeTaprootOutputKey(internalKey.PubKey(), rootHash.CloneBytes())
var expected, _ = payment.FromTweakedKey(tweakedKey, &network.Regtest, blindingKey.PubKey())
var expectedAddr, _ = expected.ConfidentialTaprootAddress()

func TestFromTaprootScriptTreeHash(t *testing.T) {
	p2tr, err := payment.FromTaprootScriptTreeHash(
		internalKey.PubKey(),
		&rootHash,
		&network.Regtest,
		blindingKey.PubKey(),
	)

	if err != nil {
		t.Error(err)
	}

	if p2tr.Taproot.RootScriptTreeHash != &rootHash {
		t.Error("Root script tree hash not set")
	}

	if !bytes.Equal(p2tr.Taproot.XOnlyInternalKey, schnorr.SerializePubKey(internalKey.PubKey())) {
		t.Error("Internal key not set incorrect")
	}

	addr, err := p2tr.ConfidentialTaprootAddress()
	if err != nil {
		t.Error(err)
	}

	typeOfAddr, err := address.DecodeType(addr)
	if err != nil {
		t.Error(err)
	}

	if typeOfAddr != address.ConfidentialP2TR {
		t.Error("Address type not set correctly")
	}

	if expectedAddr != addr {
		t.Errorf("Expected address %s, got %s", expectedAddr, addr)
	}
}

func TestFromTaprootScriptTree(t *testing.T) {
	p2tr, err := payment.FromTaprootScriptTree(
		internalKey.PubKey(),
		testTree,
		&network.Regtest,
		blindingKey.PubKey(),
	)

	if err != nil {
		t.Error(err)
	}

	if p2tr.Taproot.ScriptTree == nil {
		t.Error("Script tree not set")
	}

	if !bytes.Equal(p2tr.Taproot.XOnlyInternalKey, schnorr.SerializePubKey(internalKey.PubKey())) {
		t.Error("Internal key incorrect")
	}

	addr, err := p2tr.ConfidentialTaprootAddress()
	if err != nil {
		t.Error(err)
	}

	typeOfAddr, err := address.DecodeType(addr)
	if err != nil {
		t.Error(err)
	}

	if typeOfAddr != address.ConfidentialP2TR {
		t.Error("Address type not set correctly")
	}

	if expectedAddr != addr {
		t.Errorf("Expected address %s, got %s", expectedAddr, addr)
	}
}

func TestTaprootAddressWithNonTaprootPayment(t *testing.T) {
	pay := payment.Payment{
		Network:     &network.Regtest,
		BlindingKey: expected.BlindingKey,
		Taproot:     nil,
	}

	_, err := pay.ConfidentialTaprootAddress()
	if err != payment.ErrTaprootDataIsNil {
		t.Errorf("Expected ErrTaprootDataIsNil, got %v", err)
	}

	_, err = pay.TaprootAddress()
	if err != payment.ErrTaprootDataIsNil {
		t.Errorf("Expected ErrTaprootDataIsNil, got %v", err)
	}
}

func TestTaprootAddressWithoutNetwork(t *testing.T) {
	p2tr, err := payment.FromTaprootScriptTree(
		internalKey.PubKey(),
		testTree,
		nil,
		blindingKey.PubKey(),
	)

	p2tr.Network = nil

	if err != nil {
		t.Error(err)
	}

	_, err = p2tr.ConfidentialTaprootAddress()
	if err != payment.ErrNetworkIsNil {
		t.Errorf("Expected ErrNetworkIsNil, got %v", err)
	}
}
