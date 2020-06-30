package address_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
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
	if len(bech32.Program) != 33 && len(bech32.Program) != 20 {
		t.Errorf("TestFromBech32: data size mismatch")
	}
	bc32, _ := address.ToBech32(&address.Bech32{bech32.Prefix, bech32.Version, bech32.Program})
	if bc32 != bech32address {
		t.Errorf("TestToBech32: wrong anddress")
	}

}

func TestToBlech32_P2WPKH(t *testing.T) {
	pkBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		t.Error(err)
	}

	witProg1Bytes, err := hex.DecodeString(witProg1)
	if err != nil {
		t.Error(err)
	}

	blech32Addr := &address.Blech32{
		Prefix:    "el",
		Version:   0,
		PublicKey: pkBytes,
		Program:   witProg1Bytes,
	}

	blech32, err := address.ToBlech32(blech32Addr)
	if err != nil {
		t.Error(err)
	}

	if addr1 != blech32 {
		t.Error("TestToBlech32_P2WPKH: blech32 encoding error")
	}
}

func TestToBlech32_P2WSH(t *testing.T) {
	pkBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		t.Error(err)
	}

	witProg2Bytes, err := hex.DecodeString(witProg2)
	if err != nil {
		t.Error(err)
	}

	blech32Addr := &address.Blech32{
		Prefix:    "el",
		Version:   0,
		PublicKey: pkBytes,
		Program:   witProg2Bytes,
	}

	blech32, err := address.ToBlech32(blech32Addr)
	if err != nil {
		t.Error(err)
	}

	if addr2 != blech32 {
		t.Error("TestToBlech32_P2WSH: blech32 encoding error")
	}
}

func TestFromBlech32_P2WPKH(t *testing.T) {
	blech32, err := address.FromBlech32(addr1)
	if err != nil {
		t.Error(err)
	}
	if blech32.Version != 0 {
		t.Error("TestFromBlech32_P2WPKH: wrong version")
	}

	resPubKey := blech32.PublicKey
	if hex.EncodeToString(resPubKey) != pubKey {
		t.Error("TestFromBlech32_P2WPKH: wrong pub key")
	}

	resProgram := blech32.Program
	if hex.EncodeToString(resProgram) != witProg1 {
		t.Error("TestFromBlech32_P2WPKH: wrong witness program")
	}
}

func TestFromBlech32_P2WSH(t *testing.T) {
	blech32, err := address.FromBlech32(addr2)
	if err != nil {
		t.Error(err)
	}
	if blech32.Version != 0 {
		t.Error("TestFromBlech32_P2WSH: wrong version")
	}

	resPubKey := blech32.PublicKey
	if hex.EncodeToString(resPubKey) != pubKey {
		t.Error("TestFromBlech32_P2WSH: wrong pub key")
	}

	resProgram := blech32.Program
	if hex.EncodeToString(resProgram) != witProg2 {
		t.Error("TestFromBlech32_P2WSH: wrong witness program")
	}
}

func TestDecodeAddressTypeP2Pkh(t *testing.T) {
	addr := "Q9863Eah5byyxdBX8zghpooS2x4Ey8XZyc"
	addressType, err := address.DecodeType(addr, network.Liquid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.P2Pkh, addressType)
}

func TestDecodeAddressTypeP2sh(t *testing.T) {
	addr := "H5RCjtzndKyzFnVe41yg62T3WViWguyz4M"
	addressType, err := address.DecodeType(addr, network.Liquid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.P2Sh, addressType)
}

func TestDecodeAddressTypeConfidentialP2Pkh(t *testing.T) {
	addr := "VTpuLYhJwE8CFm6h1A6DASCaJuRQqkBt6qGfbebSHAUxGXsJMo8wtRvLZYZSWWXt8" +
		"9jG55pCF4YfxMjh"
	addressType, err := address.DecodeType(addr, network.Liquid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.ConfidentialP2Pkh, addressType)
}

func TestDecodeAddressTypeConfidentialP2sh(t *testing.T) {
	addr := "VJLDHFUbw8oPUcwzmf9jw4tZdN57rEfAusRmWy6knHAF2a4rLGenJz5WPVuyggVzQ" +
		"PHY6JjzKuw31B6e"
	addressType, err := address.DecodeType(addr, network.Liquid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.ConfidentialP2Sh, addressType)
}

func TestDecodeAddressTypeP2wpkh(t *testing.T) {
	addr := "ex1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5vqrmu3"

	addressType, err := address.DecodeType(addr, network.Liquid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.P2Wpkh, addressType)
}

func TestDecodeAddressTypeConfidentialP2wpkh(t *testing.T) {
	addr := "lq1qqwrdmhm69vsq3qfym06tlyhfze9ltauay9tv4r34ueplfwtjx0q27dk2c4d3a" +
		"9ms6wum04efclqph7dg4unwcmwmw4vnqreq3"
	addressType, err := address.DecodeType(addr, network.Liquid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.ConfidentialP2Wpkh, addressType)
}

func TestDecodeAddressTypeP2wsh(t *testing.T) {
	addr := "ert1q2z45rh444qmeand48lq0wp3jatxs2nzh492ds9s5yscv2pplxwesajz7q3"
	addressType, err := address.DecodeType(addr, network.Regtest)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.P2Wsh, addressType)
}

func TestDecodeAddressTypeConfidentialP2wsh(t *testing.T) {
	addr := "lq1qq2akvug2el2rg6lt6aewh9rzy7dglf9ajdmrkknnwwl3jwxgfkh985x3lrzmr" +
		"q2mc3c6aa85wgxxfm9v8r062qwq4ty579p54pn2q2hqnhgwv394ycf8"
	addressType, err := address.DecodeType(addr, network.Liquid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, address.ConfidentialP2Wsh, addressType)
}
