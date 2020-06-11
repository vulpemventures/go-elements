package slip77

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromSeed(t *testing.T) {
	file, err := ioutil.ReadFile("data/slip77.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, testVector := range tests["fromSeed"].([]interface{}) {
		v := testVector.(map[string]interface{})
		seed, _ := hex.DecodeString(v["seed"].(string))

		slip77Node, err := FromSeed(seed)
		if !assert.NoError(t, err) {
			t.Fatal(err)
		}

		expected := v["expected"].(string)
		assert.Equal(t, expected, hex.EncodeToString(slip77Node.MasterKey))
	}
}

func TestDeriveKey(t *testing.T) {
	file, err := ioutil.ReadFile("data/slip77.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, testVector := range tests["deriveKey"].([]interface{}) {
		v := testVector.(map[string]interface{})
		script, _ := hex.DecodeString(v["script"].(string))
		masterKey, _ := hex.DecodeString(v["masterKey"].(string))

		slip77Node, err := FromMasterKey(masterKey)
		if err != nil {
			t.Fatal(err)
		}

		privKey, pubKey, err := slip77Node.DeriveKey(script)
		if err != nil {
			t.Fatal(err)
		}

		serializedPrivKey := hex.EncodeToString(privKey.Serialize())
		serializedPubKey := hex.EncodeToString(pubKey.SerializeCompressed())

		assert.Equal(
			t,
			v["expectedPrivKey"].(string),
			serializedPrivKey,
		)
		assert.Equal(
			t,
			v["expectedPubKey"].(string),
			serializedPubKey,
		)
	}
}
