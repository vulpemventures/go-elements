package address

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/network"
)

func TestBase58(t *testing.T) {
	addresses := []string{
		"XFKcLWJmPuToz62uc2sgCBUddmH6yopoxE",
		"2dnTicaj6kay4FAV1N9qNDNawYehaxpifkP",
	}

	for _, addr := range addresses {
		base58, err := FromBase58(addr)
		if err != nil {
			t.Fatal(err)
		}
		gotAddr := ToBase58(base58)
		assert.Equal(t, addr, gotAddr)
	}
}

func TestBech32(t *testing.T) {
	addresses := []string{
		"ert1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5kjfrrt",
		"ert1qyny4kp4adanuu670vfrnz7t384s8gvdtnwr0jcvvrwqwar4t9qcs2m7c20",
	}

	for _, addr := range addresses {
		b32, err := FromBech32(addr)
		if err != nil {
			t.Fatal(err)
		}
		gotAddr, err := ToBech32(b32)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, addr, gotAddr)
	}
}

func TestBase58Confidential(t *testing.T) {
	addresses := []string{
		"CTEvndySQ8VCBNmc7LGcGVm43eTqwWdCzFTSD7bjd4bJs7ti181aQnwADXXCzJPbANkSEpeVq19yck8N",
		"AzppxC5RDs8yB8mabhwS13y4WbsWoS41fLV8GKM4woLUJB5RxNBVfK6wdVX4QVoubRXFKKfbPhEKKTKc",
	}

	for _, addr := range addresses {
		base58, err := FromBase58Confidential(addr)
		if err != nil {
			t.Fatal(err)
		}
		gotAddr := ToBase58Confidential(base58)
		assert.Equal(t, addr, gotAddr)
	}
}

func TestBlech32(t *testing.T) {
	addresses := []string{
		"el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
		"el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz",
	}

	for _, addr := range addresses {
		b32, err := FromBlech32(addr)
		if err != nil {
			t.Fatal(err)
		}
		gotAddr, err := ToBlech32(b32)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, addr, gotAddr)
	}
}

func TestConfidential(t *testing.T) {
	addresses := []string{
		"CTEvndySQ8VCBNmc7LGcGVm43eTqwWdCzFTSD7bjd4bJs7ti181aQnwADXXCzJPbANkSEpeVq19yck8N",
		"AzppxC5RDs8yB8mabhwS13y4WbsWoS41fLV8GKM4woLUJB5RxNBVfK6wdVX4QVoubRXFKKfbPhEKKTKc",
		"el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd",
		"el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz",
	}

	for _, addr := range addresses {
		res, err := FromConfidential(addr)
		if err != nil {
			t.Fatal(err)
		}
		gotAddr, err := ToConfidential(res)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, addr, gotAddr)
	}
}

func TestDecodeAddressType(t *testing.T) {
	tests := []struct {
		address      string
		network      network.Network
		expectedType int
	}{
		{
			address:      "Q9863Eah5byyxdBX8zghpooS2x4Ey8XZyc",
			network:      network.Liquid,
			expectedType: P2Pkh,
		},
		{
			address:      "H5RCjtzndKyzFnVe41yg62T3WViWguyz4M",
			network:      network.Liquid,
			expectedType: P2Sh,
		},
		{
			address:      "ex1qlg343tpldc4wvjxn3jdq2qs35r8j5yd5vqrmu3",
			network:      network.Liquid,
			expectedType: P2Wpkh,
		},
		{
			address:      "ert1q2z45rh444qmeand48lq0wp3jatxs2nzh492ds9s5yscv2pplxwesajz7q3",
			network:      network.Regtest,
			expectedType: P2Wsh,
		},
		{
			address:      "VTpuLYhJwE8CFm6h1A6DASCaJuRQqkBt6qGfbebSHAUxGXsJMo8wtRvLZYZSWWXt89jG55pCF4YfxMjh",
			network:      network.Liquid,
			expectedType: ConfidentialP2Pkh,
		},
		{
			address:      "VJLDHFUbw8oPUcwzmf9jw4tZdN57rEfAusRmWy6knHAF2a4rLGenJz5WPVuyggVzQPHY6JjzKuw31B6e",
			network:      network.Liquid,
			expectedType: ConfidentialP2Sh,
		},
		{
			address:      "lq1qqwrdmhm69vsq3qfym06tlyhfze9ltauay9tv4r34ueplfwtjx0q27dk2c4d3a9ms6wum04efclqph7dg4unwcmwmw4vnqreq3",
			network:      network.Liquid,
			expectedType: ConfidentialP2Wpkh,
		},
		{
			address:      "lq1qq2akvug2el2rg6lt6aewh9rzy7dglf9ajdmrkknnwwl3jwxgfkh985x3lrzmrq2mc3c6aa85wgxxfm9v8r062qwq4ty579p54pn2q2hqnhgwv394ycf8",
			network:      network.Liquid,
			expectedType: ConfidentialP2Wsh,
		},
	}

	for _, tt := range tests {
		addressType, err := DecodeType(tt.address, tt.network)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, tt.expectedType, addressType)
	}
}

func h2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}
