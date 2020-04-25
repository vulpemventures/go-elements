package address_test

import (
	"testing"
	"encoding/hex"
	"github.com/vulpemventures/go-elements/address"
)

const (
	base58address = "XFKcLWJmPuToz62uc2sgCBUddmH6yopoxE"
	base58hexdata = "2b919bfc040faed8de5469dfa0241a3c1e5681be"
	bech32hexdata = "e6a10b7bd8aeb56444c5734ea682cd2f1ad692c4"
	bech32address = "ert1qu6ssk77c466kg3x9wd82dqkd9udddykyfykm9k"
)

func TestFromBase58(t *testing.T) {
	base58, err := address.FromBase58(base58address)
	if err != nil {
		t.Errorf("TestFromBase58: base58 decoding error")
	}

	if base58.Version != 75 {
		t.Errorf("TestFromBase58: wrong version")
	}

	if len(base58.Data) != 20 {
		t.Errorf("TestFromBase58: data size mismatch")
	}
} 

func TestToBase58(t *testing.T) {
	data, _ := hex.DecodeString(base58hexdata)
	payload := &address.Base58{75, data}
	addr := address.ToBase58(payload)
	if addr != base58address {
		t.Errorf("TestToBase58: base58 encoding error")
	}
}

func TestBech32(t *testing.T) {
	bech32, err := address.FromBech32(bech32address)
	if err != nil {
		t.Errorf("TestFromBech32: bech32 decoding error")
	}
	if bech32.Prefix != "ert" {
		t.Errorf("TestBech32: wrong prefix")
	}
	if len(bech32.Data) != 33 {
		t.Errorf("TestBech32: data size mismatch")
	}
	data, _ := hex.DecodeString(bech32hexdata)
	payload := &address.Bech32{"ert", data}
	addr, _ := address.ToBech32(payload)
	println(addr)
}