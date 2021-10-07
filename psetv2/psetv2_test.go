package psetv2

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestNewFromHex(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/deserialize.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []map[string]interface{}
	err = json.Unmarshal(file, &tests)

	for _, v := range tests {
		testName := v["name"].(string)
		t.Run(testName, func(t *testing.T) {
			_, err := NewFromHex(v["hex"].(string))
			if err != nil {
				t.Errorf("test: %v, err: %v", testName, err)
			}
		})
	}
}
