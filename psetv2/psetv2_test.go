package psetv2

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeserializationAndSerialization(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/deserialize.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []map[string]interface{}
	err = json.Unmarshal(file, &tests)

	for _, v := range tests {
		testName := v["name"].(string)
		t.Run(testName, func(t *testing.T) {
			ptx, err := NewFromHex(v["hex"].(string))
			if err != nil {
				t.Errorf("test: %v, err: %v", testName, err)
				return
			}

			hex, err := ptx.ToHex()
			if err != nil {
				t.Errorf("test: %v, err: %v", testName, err)
				return
			}

			assert.Equal(t, v["hex"].(string), hex)
		})
	}
}
