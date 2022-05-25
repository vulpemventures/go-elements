package blech32_test

import (
	"strings"
	"testing"

	"github.com/vulpemventures/go-elements/blech32"
)

type fixture struct {
	enc     blech32.EncodingType
	valid   []string
	invalid []string
}

func makeTest(f fixture, t *testing.T) {
	for _, s := range f.valid {
		t.Run(s, func(t *testing.T) {
			hrp, data, _, err := blech32.DecodeGeneric(s)
			if err != nil {
				t.Errorf("%v: %v", s, err)
			}

			str, err := blech32.Encode(hrp, data, f.enc)
			if err != nil {
				t.Errorf("%v: %v", s, err)
			}

			if str != strings.ToLower(s) {
				t.Errorf("%v: %v != %v", s, str, s)
			}
		})
	}
	for _, s := range f.invalid {
		t.Run(s, func(t *testing.T) {
			_, _, _, err := blech32.DecodeGeneric(s)
			if err == nil {
				t.Errorf("%v: expected error", s)
			}
		})
	}
}

var blech32fixture = fixture{
	enc: blech32.BLECH32,
	valid: []string{
		"A133NZFWEYK7UT",
		"a133nzfweyk7ut",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio195jhgldwsn5j",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lgmcn7l7t7xve",
		"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xldwlutcw2l",
		"split1checkupstagehandshakeupstreamerranterredcaperredegneyqml9esp",
		"?19dv34t3p4s35",
	},
	invalid: []string{
		" 1nwldj5",
		"\x7f1axkwrx",
		"\x801eym55h",
		"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
		"pzry9x0s0muk",
		"1pzry9x0s0muk",
		"x1b4n0q5v",
		"li1dgmt3",
		"de1lg7wt\xff",
		"A1G7SGD8",
		"10a06t8",
		"1qzzfhee",
		"a12UEL5L",
		"A12uEL5L",
	},
}

var blech32mFixture = fixture{
	enc: blech32.BLECH32M,
	valid: []string{
		"A1EYL4VXQ3HRPT",
		"a1eyl4vxq3hrpt",
		"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11yatn6l85muud",
		"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqg8m5pqg67zq3",
		"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll09wxh8ajdvxv",
		"split1checkupstagehandshakeupstreamerranterredcaperred3alwpgz2yydp",
		"?1dcqxsrg55dv5",
	},
	invalid: []string{
		" 1xj0phk",
		"\x7f1g6xzxy",
		"\x801vctc34",
		"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
		"qyrz8wqd2c9m",
		"1qyrz8wqd2c9m",
		"y1b0jsk6g",
		"lt1igcx5c0",
		"in1muywd",
		"mm1crxm3i",
		"au1s5cgom",
		"M1VUXWEZ",
		"16plkw9",
		"1p2gdwpf",
	},
}

func TestBlech32(t *testing.T) {
	makeTest(blech32fixture, t)
}

func TestBlech32m(t *testing.T) {
	makeTest(blech32mFixture, t)
}
