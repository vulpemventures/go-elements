package psetv2test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vulpemventures/go-elements/confidential"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"

	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"

	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
)

var lbtc = append(
	[]byte{0x01},
	elementsutil.ReverseBytes(h2b(network.Regtest.AssetID))...,
)

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

func apiBaseUrl() (string, error) {
	u, ok := os.LookupEnv("API_URL")
	if !ok {
		return "", errors.New("API_URL environment variable is not set")
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

func addFeesToTransaction(p *psetv2.Pset, feeAmount uint64) error {
	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(feeAmount)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)

	outputArg := psetv2.OutputArg{TxOutput: *feeOutput}
	updaterRole, _ := psetv2.NewUpdaterRole(p)

	return updaterRole.AddOutput(outputArg)
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
	blinderSvc confidential.Blinder,
) error {
	updaterRole, err := psetv2.NewUpdaterRole(p)
	if err != nil {
		return err
	}

	signerRole, err := psetv2.NewSignerRole(p, blinderSvc)
	if err != nil {
		return err
	}

	for k, v := range p.Inputs {
		updaterRole.AddInSighashType(txscript.SigHashAll|transaction.SighashRangeproof, k)

		var prevout *transaction.TxOutput
		if v.WitnessUtxo() != nil {
			prevout = v.WitnessUtxo()
		} else {
			prevout = v.NonWitnessUtxo().Outputs[k]
		}
		prvkey := privKeys[k]
		pubkey := prvkey.PubKey()
		script := scripts[k]

		var sigHash [32]byte
		tx, err := p.UnsignedTx(blinderSvc)
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

		var witPubkeyScript []byte
		var witScript []byte
		if opts != nil {
			witPubkeyScript = opts.pubkeyScript
			witScript = opts.script
		}

		if _, err := signerRole.SignInput(
			k,
			sigWithHashType,
			pubkey.SerializeCompressed(),
			witPubkeyScript,
			witScript,
		); err != nil {
			return err
		}
	}

	valid, err := signerRole.ValidateAllSignatures()
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid signatures")
	}

	return nil
}

func broadcastTransaction(p *psetv2.Pset, blinderSvc psetv2.Blinder) (string, error) {
	finalizerRole := psetv2.NewFinalizerRole(p)
	if err := finalizerRole.FinalizeAll(p); err != nil {
		return "", err
	}
	// Extract the final signed transaction from the Pset wrapper.

	extractorRole := psetv2.NewExtractorRole(p, blinderSvc)
	finalTx, err := extractorRole.Extract()
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
