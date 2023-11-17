package psetv2_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vulpemventures/go-elements/network"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/txscript"

	"github.com/vulpemventures/go-elements/psetv2"
)

var lbtc = network.Regtest.AssetID

func faucet(address string, args ...interface{}) (string, error) {
	baseURL, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/faucet", baseURL)
	payload := map[string]interface{}{"address": address, "amount": 1}
	if len(args) > 0 {
		for _, arg := range args {
			if amount, ok := arg.(float64); ok {
				payload["amount"] = amount
			}
			if asset, ok := arg.(string); ok {
				payload["asset"] = asset
			}
		}
	}
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
	p *psetv2.Pset, privKeys []*btcec.PrivateKey, scripts [][]byte,
	forWitness bool, sighashType txscript.SigHashType, opts *signOpts,
) error {
	signer, err := psetv2.NewSigner(p)
	if err != nil {
		return err
	}

	for i, in := range p.Inputs {
		if len(in.PartialSigs) > 0 {
			continue
		}

		if err := signer.AddInSighashType(i, sighashType); err != nil {
			return err
		}

		prevout := in.GetUtxo()
		prvkey := privKeys[i]
		pubkey := prvkey.PubKey()
		script := scripts[i]

		var sigHash [32]byte
		tx, err := p.UnsignedTx()
		if err != nil {
			return err
		}

		if forWitness {
			sigHash = tx.HashForWitnessV0(i, script, prevout.Value, sighashType)
		} else {
			sigHash, err = tx.HashForSignature(i, script, sighashType)
			if err != nil {
				return err
			}
		}

		sig := ecdsa.Sign(prvkey, sigHash[:])
		sigWithHashType := append(sig.Serialize(), byte(sighashType))

		var witPubkeyScript, witScript []byte
		if opts != nil {
			witPubkeyScript = opts.pubkeyScript
			witScript = opts.script
		}

		if err := signer.SignInput(
			i, sigWithHashType, pubkey.SerializeCompressed(),
			witPubkeyScript, witScript,
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

func signInput(
	p *psetv2.Pset, inIndex int, prvkey *btcec.PrivateKey, script []byte,
	forWitness bool, sighashType txscript.SigHashType, opts *signOpts,
) error {
	signer, err := psetv2.NewSigner(p)
	if err != nil {
		return err
	}

	in := p.Inputs[inIndex]
	if len(in.PartialSigs) > 0 {
		return nil
	}

	if err := signer.AddInSighashType(inIndex, sighashType); err != nil {
		return err
	}

	prevout := in.GetUtxo()
	pubkey := prvkey.PubKey()

	var sigHash [32]byte
	tx, err := p.UnsignedTx()
	if err != nil {
		return err
	}

	if forWitness {
		sigHash = tx.HashForWitnessV0(inIndex, script, prevout.Value, sighashType)
	} else {
		sigHash, err = tx.HashForSignature(inIndex, script, sighashType)
		if err != nil {
			return err
		}
	}

	sig := ecdsa.Sign(prvkey, sigHash[:])
	sigWithHashType := append(sig.Serialize(), byte(sighashType))

	var witPubkeyScript, witScript []byte
	if opts != nil {
		witPubkeyScript = opts.pubkeyScript
		witScript = opts.script
	}

	if err := signer.SignInput(
		inIndex, sigWithHashType, pubkey.SerializeCompressed(),
		witPubkeyScript, witScript,
	); err != nil {
		return err
	}

	valid, err := p.ValidateInputSignatures(inIndex)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func extractAndBroadcast(p *psetv2.Pset) (string, error) {
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

func randomHex(len int) string {
	return hex.EncodeToString(randomBytes(len))
}

func randomVout() uint32 {
	return uint32(randomIntInRange(0, 15))
}

func randomValue() uint64 {
	return uint64(randomIntInRange(1000000, 10000000000))
}

func randomBytes(len int) []byte {
	b := make([]byte, len)
	rand.Read(b)
	return b
}

func randomIntInRange(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(int(n.Int64())) + min
}
