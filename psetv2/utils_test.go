package psetv2_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vulpemventures/go-elements/network"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"

	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

var lbtc = network.Regtest.AssetID

func faucet(address string) (string, error) {
	baseURL, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/faucet", baseURL)
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

func mint(address string, quantity int, name string, ticker string) (string, string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", "", err
	}

	url := fmt.Sprintf("%s/mint", baseUrl)
	payload := map[string]interface{}{
		"address":  address,
		"quantity": quantity,
		"name":     name,
		"ticker":   ticker,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if res := string(data); len(res) <= 0 || strings.Contains(res, "sendtoaddress") {
		return "", "", fmt.Errorf("cannot fund address with minted asset: %s", res)
	}

	respBody := map[string]interface{}{}
	if err := json.Unmarshal(data, &respBody); err != nil {
		return "", "", err
	}
	return respBody["txId"].(string), respBody["asset"].(string), nil
}

func apiBaseUrl() (string, error) {
	u, ok := os.LookupEnv("API_URL")
	if !ok {
		return "", fmt.Errorf("API_URL environment variable is not set")
	}
	return u, nil
}

func unspents(address string) ([]map[string]interface{}, error) {
	getUtxos := func(address string) ([]interface{}, error) {
		baseUrl, err := apiBaseUrl()
		if err != nil {
			return nil, err
		}
		url := fmt.Sprintf("%s/address/%s/utxo", baseUrl, address)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var respBody interface{}
		if err := json.Unmarshal(data, &respBody); err != nil {
			return nil, err
		}
		return respBody.([]interface{}), nil
	}

	utxos := []map[string]interface{}{}
	for len(utxos) <= 0 {
		time.Sleep(1 * time.Second)
		u, err := getUtxos(address)
		if err != nil {
			return nil, err
		}
		for _, unspent := range u {
			utxo := unspent.(map[string]interface{})
			utxos = append(utxos, utxo)
		}
	}

	return utxos, nil
}

func b2h(buf []byte) string {
	return hex.EncodeToString(buf)
}

func h2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}

func fetchTx(txId string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx/%s/hex", baseUrl, txId)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

type signOpts struct {
	pubkeyScript []byte
	script       []byte
}

func signTransaction(
	p *psetv2.Pset,
	privKeys []*btcec.PrivateKey,
	scripts [][]byte,
	forWitness bool,
	opts *signOpts,
) error {
	signer, err := psetv2.NewSigner(p)
	if err != nil {
		return err
	}

	for k, v := range p.Inputs {
		if err := signer.AddInSighashType(
			txscript.SigHashAll|transaction.SighashRangeproof, 0,
		); err != nil {
			return err
		}

		prevout := v.GetUtxo()
		prvkey := privKeys[k]
		pubkey := prvkey.PubKey()
		script := scripts[k]

		var sigHash [32]byte
		tx, err := p.UnsignedTx()
		if err != nil {
			return err
		}

		if forWitness {
			sigHash = tx.HashForWitnessV0(
				k,
				script,
				prevout.Value,
				txscript.SigHashAll|transaction.SighashRangeproof,
			)
		} else {
			sigHash, err = tx.HashForSignature(k, script, txscript.SigHashAll|transaction.SighashRangeproof)
			if err != nil {
				return err
			}
		}

		sig, err := prvkey.Sign(sigHash[:])
		if err != nil {
			return err
		}
		sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll|transaction.SighashRangeproof))

		var witPubkeyScript, witScript []byte
		if opts != nil {
			witPubkeyScript = opts.pubkeyScript
			witScript = opts.script
		}

		if err := signer.SignInput(
			k,
			sigWithHashType,
			pubkey.SerializeCompressed(),
			witPubkeyScript,
			witScript,
		); err != nil {
			return err
		}
	}

	valid, err := p.ValidateAllSignatures()
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid signatures")
	}

	return nil
}

func broadcastTransaction(p *psetv2.Pset) (string, error) {
	if err := psetv2.FinalizeAll(p); err != nil {
		return "", err
	}
	// Extract the final signed transaction from the Pset wrapper.

	finalTx, err := psetv2.Extract(p)
	if err != nil {
		return "", err
	}
	// Serialize the transaction and try to broadcast.
	txHex, err := finalTx.ToHex()
	if err != nil {
		return "", err
	}

	return broadcast(txHex)
}

func broadcast(txHex string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx", baseUrl)

	resp, err := http.Post(url, "text/plain", strings.NewReader(txHex))
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	res := string(data)
	if len(res) <= 0 || strings.Contains(res, "sendrawtransaction") {
		return "", fmt.Errorf("failed to broadcast tx: %s", res)
	}
	return res, nil
}
