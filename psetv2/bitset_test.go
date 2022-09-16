package psetv2_test

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/psetv2"
)

func TestBitSet(t *testing.T) {
	var tests map[string]interface{}
	file, _ := ioutil.ReadFile("testdata/bitset.json")
	json.Unmarshal(file, &tests)

	valid := tests["valid"].([]interface{})

	t.Run("valid", func(t *testing.T) {
		for _, v := range valid {
			tt := v.(map[string]interface{})
			value := byte((tt["value"].(float64)))
			expected := tt["expected"].(string)
			bitset, err := psetv2.NewBitSetFromBuffer(value)
			require.NoError(t, err)
			require.NotNil(t, bitset)
			require.Equal(t, expected, bitset.String())
		}
	})
}
