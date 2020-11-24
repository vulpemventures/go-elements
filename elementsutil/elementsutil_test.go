package elementsutil

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSatoshiToElementsValueRoundTrip(t *testing.T) {
	bigInt, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		panic(err)
	}
	satoshi := bigInt.Uint64()
	elementsValue, err := SatoshiToElementsValue(satoshi)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	satoshiValue, err := ElementsToSatoshiValue(elementsValue)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, satoshi, satoshiValue)
}
