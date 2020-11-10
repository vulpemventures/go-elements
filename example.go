package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/pset"
	"github.com/vulpemventures/go-elements/transaction"
)

const baseUrl = "http://localhost:3001"

func faucet(address string) (string, error) {
	url := baseUrl + "/faucet"
	payload := map[string]string{"address": address}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "appliation/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	respBody := map[string]string{}
	err = json.Unmarshal(data, &respBody)
	if err != nil {
		return "", err
	}

	return respBody["txId"], nil
}

func mint(address string, quantity int, name string, ticker string) (string, error) {
	url := baseUrl + "/mint"
	payload := map[string]interface{}{"address": address, "quantity": quantity, "name": name, "ticker": ticker}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "appliation/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	respBody := map[string]interface{}{}

	err = json.Unmarshal(data, &respBody)
	if err != nil {
		return "", err
	}
	return respBody["txId"].(string), nil
}

func unspents(address string) ([]map[string]interface{}, error) {
	getUtxos := func(address string) ([]interface{}, error) {
		url := baseUrl + "/address/" + address + "/utxo"
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var respBody interface{}
		err = json.Unmarshal(data, &respBody)
		if err != nil {
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

func main() {
	// Generating Alices Keys and Address
	privkeyAlice, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic(err)
	}
	pubkeyAlice := privkeyAlice.PubKey()
	p2wpkhAlice := payment.FromPublicKey(pubkeyAlice, &network.Regtest, nil)
	addressAlice, _ := p2wpkhAlice.WitnessPubKeyHash()

	// Generating Bobs Keys and Address
	privkeyBob, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic(err)
	}
	pubkeyBob := privkeyBob.PubKey()
	p2wpkhBob := payment.FromPublicKey(pubkeyBob, &network.Regtest, nil)
	addressBob, _ := p2wpkhBob.WitnessPubKeyHash()

	// Fund Alice address with LBTC.
	_, err = faucet(addressAlice)
	time.Sleep(time.Second)
	if err != nil {
		panic(err)
	}

	// Fund Bob address with an asset.
	_, err = mint(addressBob, 1000, "VULPEM", "VLP")
	time.Sleep(time.Second)
	if err != nil {
		panic(err)
	}

	// Retrieve Alice utxos.
	utxosAlice, err := unspents(addressAlice)
	if err != nil {
		panic(err)
	}

	// Retrieve Bob utxos.
	utxosBob, err := unspents(addressBob)
	if err != nil {
		panic(err)
	}

	// The transaction will have 2 input and 3 outputs.
	// Input From Alice
	txInputHashAlice, _ := hex.DecodeString(utxosAlice[0]["txid"].(string))
	txInputHashAlice = bufferutil.ReverseBytes(txInputHashAlice)
	txInputIndexAlice := uint32(utxosAlice[0]["vout"].(float64))
	txInputAlice := transaction.NewTxInput(txInputHashAlice, txInputIndexAlice)
	// Input From Bob
	txInputHashBob, _ := hex.DecodeString(utxosBob[0]["txid"].(string))
	txInputHashBob = bufferutil.ReverseBytes(txInputHashBob)
	txInputIndexBob := uint32(utxosBob[0]["vout"].(float64))
	txInputBob := transaction.NewTxInput(txInputHashBob, txInputIndexBob)

	//// Outputs from Alice
	// LBTC to Bob
	lbtc, _ := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	)
	lbtc = append([]byte{0x01}, bufferutil.ReverseBytes(lbtc)...)
	aliceToBobValue, _ := confidential.SatoshiToElementsValue(60000000)
	aliceToBobScript := p2wpkhBob.WitnessScript
	aliceToBobOutput := transaction.NewTxOutput(lbtc, aliceToBobValue[:], aliceToBobScript)
	// Change from/to Alice
	changeScriptAlice := p2wpkhAlice.WitnessScript
	changeValueAlice, _ := confidential.SatoshiToElementsValue(39999500)
	changeOutputAlice := transaction.NewTxOutput(lbtc, changeValueAlice[:], changeScriptAlice)

	// Asset hex
	asset, _ := hex.DecodeString(
		utxosBob[0]["asset"].(string),
	)
	asset = append([]byte{0x01}, bufferutil.ReverseBytes(asset)...)

	//// Outputs from Bob
	// Asset to Alice
	bobToAliceValue, _ := confidential.SatoshiToElementsValue(100000000000)
	bobToAliceScript := p2wpkhAlice.WitnessScript
	bobToAliceOutput := transaction.NewTxOutput(asset, bobToAliceValue[:], bobToAliceScript)

	// Create a new pset with all the outputs that need to be blinded first
	inputs := []*transaction.TxInput{txInputAlice, txInputBob}
	outputs := []*transaction.TxOutput{aliceToBobOutput, changeOutputAlice, bobToAliceOutput}
	p, err := pset.New(inputs, outputs, 2, 0)
	if err != nil {
		panic(err)
	}

	// Add sighash type and witness utxos to the partial input.
	updater, err := pset.NewUpdater(p)
	if err != nil {
		panic(err)
	}

	err = updater.AddInSighashType(txscript.SigHashAll, 0)
	if err != nil {
		panic(err)
	}
	witValueAlice, _ := confidential.SatoshiToElementsValue(uint64(utxosAlice[0]["value"].(float64)))
	witnessUtxoAlice := transaction.NewTxOutput(lbtc, witValueAlice[:], p2wpkhAlice.WitnessScript)
	err = updater.AddInWitnessUtxo(witnessUtxoAlice, 0)
	if err != nil {
		panic(err)
	}

	err = updater.AddInSighashType(txscript.SigHashAll, 1)
	if err != nil {
		panic(err)
	}
	witValueBob, _ := confidential.SatoshiToElementsValue(uint64(utxosBob[0]["value"].(float64)))
	witnessUtxoBob := transaction.NewTxOutput(asset, witValueBob[:], p2wpkhBob.WitnessScript)
	err = updater.AddInWitnessUtxo(witnessUtxoBob, 1)
	if err != nil {
		panic(err)
	}

	//blind outputs
	blindingPubKeys := make([][]byte, 0)

	pk, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic(err)
	}
	blindingpubkey := pk.PubKey().SerializeCompressed()
	blindingPubKeys = append(blindingPubKeys, blindingpubkey)

	pk1, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic(err)
	}
	blindingpubkey1 := pk1.PubKey().SerializeCompressed()
	blindingPubKeys = append(blindingPubKeys, blindingpubkey1)

	pk2, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic(err)
	}
	blindingpubkey2 := pk2.PubKey().SerializeCompressed()
	blindingPubKeys = append(blindingPubKeys, blindingpubkey2)

	blindingPrivKeys := [][]byte{pk.Serialize(), pk1.Serialize()}

	blinder, err := pset.NewBlinder(
		p,
		blindingPrivKeys,
		blindingPubKeys,
		nil,
		nil,
	)
	if err != nil {
		panic(err)
	}
	err = blinder.Blind()
	if err != nil {
		panic(err)
	}

	// Add the unblinded outputs now, that's only the fee output in this case
	feeScript := []byte{}
	feeValue, _ := confidential.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)
	updater.AddOutput(feeOutput)

	// Generate Alices Signature
	witHashAlice := updater.Data.UnsignedTx.HashForWitnessV0(0, p2wpkhAlice.Script, witValueAlice[:], txscript.SigHashAll)
	sigAlice, err := privkeyAlice.Sign(witHashAlice[:])
	if err != nil {
		panic(err)
	}
	sigWithHashTypeAlice := append(sigAlice.Serialize(), byte(txscript.SigHashAll))

	// Update the pset adding Alices input signature script and the pubkey.
	_, err = updater.Sign(0, sigWithHashTypeAlice, pubkeyAlice.SerializeCompressed(), nil, nil)
	if err != nil {
		panic(err)
	}

	// Generate Bobs Signature
	witHashBob := updater.Data.UnsignedTx.HashForWitnessV0(1, p2wpkhBob.Script, witValueBob[:], txscript.SigHashAll)
	sigBob, err := privkeyBob.Sign(witHashBob[:])
	if err != nil {
		panic(err)
	}
	sigWithHashTypeBob := append(sigBob.Serialize(), byte(txscript.SigHashAll))

	// Update the pset adding Bobs input signature script and the pubkey.
	_, err = updater.Sign(1, sigWithHashTypeBob, pubkeyBob.SerializeCompressed(), nil, nil)
	if err != nil {
		panic(err)
	}

	valid, err := updater.Data.ValidateAllSignatures()
	if err != nil {
		panic(err)
	}
	if !valid {
		panic(errors.New("invalid signatures"))
	}

	// Finalize the partial transaction.
	p = updater.Data
	err = pset.FinalizeAll(p)
	if err != nil {
		panic(err)
	}

	// Serialize the transaction and try to broadcast.
	base64, err := p.ToBase64()
	if err != nil {
		panic(err)
	}

	log.Print(base64)
}
