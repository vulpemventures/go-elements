package address_test

import (
	"testing"
	"github.com/vulpemventures/go-elements/address"
)

func TestFromBase58(t *testing.T) {
	base58, err := address.FromBase58("2dgp82cKUqN7pesBxcK6smvFSzCjyqqv1wL")
	if err != nil {
		t.Errorf("TestFromBase58: base58 decoding error")
	}

	if base58.Version != 235 {
		t.Errorf("TestFromBase58: wrong version")
	}

	if len(base58.Hash) != 20 {
		t.Errorf("TestFromBase58: hash lenght mismatch")
	}
} 