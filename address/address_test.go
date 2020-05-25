package address_test

import (
	"encoding/hex"
	"github.com/vulpemventures/go-elements/address"
	"testing"
)

const (
	base58address = "XFKcLWJmPuToz62uc2sgCBUddmH6yopoxE"
	base58hexdata = "2b919bfc040faed8de5469dfa0241a3c1e5681be"
	bech32address = "ert1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5kjfrrt"
	addr1         = "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd"
	addr2         = "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz"
	pubKey        = "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800"
	witProg1      = "e6a10b7bd8aeb56444c5734ea682cd2f1ad692c4"
	witProg2      = "332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6"
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
		t.Errorf("TestFromBech32: wrong prefix")
	}
	if bech32.Version != 0 {
		t.Errorf("TestFromBech32: wrong version")
	}
	if len(bech32.Data) != 33 && len(bech32.Data) != 20 {
		t.Errorf("TestFromBech32: data size mismatch")
	}
	bc32, _ := address.ToBech32(&address.Bech32{bech32.Prefix, bech32.Version, bech32.Data})
	if bc32 != bech32address {
		t.Errorf("TestToBech32: wrong anddress")
	}

}

func TestEncodeConfidentialP2WPKH(t *testing.T) {
	pkBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		t.Error(err)
	}

	witProg1Bytes, err := hex.DecodeString(witProg1)
	if err != nil {
		t.Error(err)
	}

	program1 := append(pkBytes, witProg1Bytes...)

	blech32, err := address.ToBlech32("el", 0x00, program1)
	if err != nil {
		t.Error(err)
	}

	if addr1 != blech32 {
		t.Error("TestEncodeConfidentialP2WPKH: blech32 encoding error")
	}
}

func TestEncodeConfidentialP2WSH(t *testing.T) {
	pkBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		t.Error(err)
	}

	witProg2Bytes, err := hex.DecodeString(witProg2)
	if err != nil {
		t.Error(err)
	}

	program2 := append(pkBytes, witProg2Bytes...)

	blech32, err := address.ToBlech32("el", 0x00, program2)
	if err != nil {
		t.Error(err)
	}

	if addr2 != blech32 {
		t.Error("TestEncodeConfidentialP2WSH: blech32 encoding error")
	}
}

func TestDecodeConfidentialP2WPKH(t *testing.T) {
	blech32, err := address.FromBlech32(addr1)
	if err != nil {
		t.Error(err)
	}
	if blech32.Version != 0 {
		t.Error("TestDecodeConfidentialP2WPKH: wrong version")
	}

	if blech32.Version != 0 {
		t.Error("TestDecodeConfidentialP2WPKH: wrong version")
	}

	resPubKey := blech32.Data[:33]
	if hex.EncodeToString(resPubKey) != pubKey {
		t.Error("TestDecodeConfidentialP2WPKH: wrong pub key")
	}

	resProgram := blech32.Data[33:]
	if hex.EncodeToString(resProgram) != witProg1 {
		t.Error("TestDecodeConfidentialP2WPKH: wrong witness program")
	}
}

func TestDecodeConfidentialP2WSH(t *testing.T) {
	blech32, err := address.FromBlech32(addr2)
	if err != nil {
		t.Error(err)
	}
	if blech32.Version != 0 {
		t.Error("TestDecodeConfidentialP2WSH: wrong version")
	}

	if blech32.Version != 0 {
		t.Error("TestDecodeConfidentialP2WSH: wrong version")
	}

	resPubKey := blech32.Data[:33]
	if hex.EncodeToString(resPubKey) != pubKey {
		t.Error("TestDecodeConfidentialP2WSH: wrong pub key")
	}

	resProgram := blech32.Data[33:]
	if hex.EncodeToString(resProgram) != witProg2 {
		t.Error("TestDecodeConfidentialP2WSH: wrong witness program")
	}
}
