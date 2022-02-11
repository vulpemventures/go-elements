package block

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"

	"github.com/vulpemventures/go-elements/elementsutil"

	"github.com/stretchr/testify/assert"
)

//some of fixtures taken from:
//https://github.com/ElementsProject/rust-elements/blob/0d67c57afa1137ab27861bb8c2190413929d4301/src/block.rs#L621
// https://github.com/ElementsProject/rust-elements/blob/0d67c57afa1137ab27861bb8c2190413929d4301/src/block.rs#L703
func TestBlockDeserialization(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/deserialize.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []map[string]interface{}
	err = json.Unmarshal(file, &tests)

	for _, v := range tests {
		testName := v["name"].(string)
		t.Run(testName, func(t *testing.T) {
			block, err := NewFromHex(v["hex"].(string))
			if err != nil {
				t.Errorf("test: %v, err: %v", testName, err)
			}

			assert.Equal(
				t,
				v["numOfTx"].(string),
				strconv.Itoa(len(block.TransactionsData.Transactions)),
			)
		})
	}
}

func TestBlockDeserializationIntegration(t *testing.T) {
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2pkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2pkh.PubKeyHash()

	// Fund sender address.
	txID, err := faucet(address)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)

	blockHash, err := getTxBlockHash(txID)
	if err != nil {
		t.Fatal(err)
	}

	rawBlock, err := getRawBlock(blockHash)
	if err != nil {
		t.Fatal(err)
	}

	block, err := NewFromBuffer(bytes.NewBuffer(rawBlock))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 2, len(block.TransactionsData.Transactions))

	for _, v := range block.TransactionsData.Transactions {
		// block will have 2 transactions: coinbase and faucet one, check faucet
		if len(v.Outputs) == 3 {
			for _, o := range v.Outputs {
				if len(o.Asset) == 9 && len(o.Script) > 0 {
					value, err := elementsutil.ValueFromBytes(
						block.TransactionsData.Transactions[1].Outputs[1].Value,
					)
					if err != nil {
						t.Fatal(err)
					}

					assert.Equal(t, uint64(100000000), value)
				}
			}
		}
	}
}

func getRawBlock(hash string) ([]byte, error) {
	baseUrl, ok := os.LookupEnv("API_URL")
	if !ok {
		return nil, errors.New("API_URL environment variable is not set")
	}

	url := fmt.Sprintf("%s/block/%s/raw", baseUrl, hash)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getTxBlockHash(txID string) (string, error) {
	baseUrl, ok := os.LookupEnv("API_URL")
	if !ok {
		return "", errors.New("API_URL environment variable is not set")
	}

	url := fmt.Sprintf("%s/tx/%s/status", baseUrl, txID)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", err
	}

	return response["block_hash"].(string), nil
}

func faucet(address string) (string, error) {
	baseUrl, ok := os.LookupEnv("API_URL")
	if !ok {
		return "nil", errors.New("API_URL environment variable is not set")
	}

	url := fmt.Sprintf("%s/faucet", baseUrl)
	payload := map[string]string{"address": address}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if res := string(data); len(res) <= 0 || strings.Contains(res, "sendtoaddress") {
		return "", fmt.Errorf("cannot fund address with faucet: %s", res)
	}

	respBody := map[string]string{}
	if err := json.Unmarshal(data, &respBody); err != nil {
		return "", err
	}
	return respBody["txId"], nil
}
