package block

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestBlockHash(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/hash.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests []struct {
		Name           string `json:"name"`
		BlockHeaderHex string `json:"blockHeaderHex"`
		Hash           string `json:"hash"`
	}

	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range tests {
		t.Run(v.Name, func(tt *testing.T) {

			blockHeader, err := hex.DecodeString(v.BlockHeaderHex)
			if err != nil {
				tt.Fatal(err)
			}

			header, err := DeserializeHeader(bytes.NewBuffer(blockHeader))
			if err != nil {
				tt.Fatal(err)
			}

			hash, err := header.GetHash()
			if err != nil {
				tt.Fatal(err)
			}

			hashHex := hex.EncodeToString(hash)

			if hashHex != v.Hash {
				tt.Errorf("hash: expected %s, got %s", v.Hash, hashHex)
			}
		})
	}
}
