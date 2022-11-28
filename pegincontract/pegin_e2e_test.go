package pegincontract

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
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/louisinger/btcd/btcec/v2"
	"github.com/louisinger/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/pegin"
)

//TestClaimPegin test e2e pegin procedure which is usually achieved using Btc Core
// and Elements node by doing following:
// 1. invoke elements cli command getpeginaddress
// 2. invoke btc cli command sendtoaddress to send some btc to mainchain address
// 3. invoke elements cli command claimpegin to claim funds
// Full tutorial in here https://elementsproject.org/elements-code-tutorial/sidechain
// Note that this test naturally belongs to pegin pkg but is placed here cause of
// intention of decoupling code related to generating contract which is using CGO
func TestClaimPegin(t *testing.T) {
	isDynaFedEnabled := false
	federationScript := "51"
	fedpegScriptBytes, err := hex.DecodeString(federationScript)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	liquidNetwork, btcNetwork := getNetworkParams(RegtestNet)

	claimScript, err := pegin.ClaimWitnessScript(
		privateKey.PubKey().SerializeCompressed(),
		liquidNetwork,
	)
	t.Log(fmt.Sprintf("claimScript: %v", hex.EncodeToString(claimScript)))

	contract, err := Calculate(
		fedpegScriptBytes,
		claimScript,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("contract: %v", hex.EncodeToString(contract)))

	mainChainAddress, err := pegin.MainChainAddress(
		contract,
		btcNetwork,
		isDynaFedEnabled,
		fedpegScriptBytes,
	)
	t.Log(fmt.Sprintf("mainchainAddress: %v", mainChainAddress))

	btcTxID, err := faucet(mainChainAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("btcTxID: %v", btcTxID))

	time.Sleep(5 * time.Second)

	btcTxHex, err := fetchTx(btcTxID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("btcTxHex: %v", btcTxHex))
	btcTxBytes, err := hex.DecodeString(btcTxHex)
	if err != nil {
		t.Fatal(err)
	}

	btcTxOutProof, err := getTxOutProof(btcTxID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("btcTxOutProof: %v", btcTxOutProof))
	btcTxOutProofBytes, err := hex.DecodeString(btcTxOutProof)

	peggedAssetBytes, err := hex.DecodeString(network.Regtest.AssetID)
	if err != nil {
		t.Fatal(err)
	}

	var lbtc = append(
		[]byte{0x01},
		elementsutil.ReverseBytes(peggedAssetBytes)...,
	)

	parentBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	parentBlockHashBytes, err := hex.DecodeString(parentBlockHash)
	if err != nil {
		t.Fatal(err)
	}

	claimTx, err := pegin.Claim(
		btcNetwork,
		isDynaFedEnabled,
		lbtc,
		parentBlockHashBytes,
		fedpegScriptBytes,
		contract,
		btcTxBytes,
		btcTxOutProofBytes,
		claimScript,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	//SIGN
	_, amount, err := pegin.GetPeginTxOutIndexAndAmount(
		btcTxBytes,
		fedpegScriptBytes,
		contract,
		btcNetwork,
		isDynaFedEnabled,
	)
	if err != nil {
		t.Fatal(err)
	}

	finalValue, err := elementsutil.ValueToBytes(uint64(amount))
	if err != nil {
		t.Fatal(err)
	}
	p := payment.FromPublicKey(privateKey.PubKey(), liquidNetwork, nil)
	sigHash := claimTx.HashForWitnessV0(
		0,
		p.Script,
		finalValue,
		txscript.SigHashAll,
	)
	sig := ecdsa.Sign(privateKey, sigHash[:])

	sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))
	witness := make([][]byte, 0)
	witness = append(witness, sigWithHashType[:])
	witness = append(witness, privateKey.PubKey().SerializeCompressed())
	claimTx.Inputs[0].Witness = witness
	claimHex, err := claimTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}

	txID, err := broadcast(claimHex)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("claimTxID: %v", txID))

	assert.NotEmpty(t, txID)
}

func getNetworkParams(
	networkType NetworkType,
) (*network.Network, *chaincfg.Params) {
	var liquidNetwork *network.Network
	var btcNetwork *chaincfg.Params
	switch networkType {
	case MainNet:
		liquidNetwork = &network.Liquid
		btcNetwork = &chaincfg.MainNetParams
	case RegtestNet:
		liquidNetwork = &network.Regtest
		btcNetwork = &chaincfg.RegressionNetParams
	}
	return liquidNetwork, btcNetwork
}

func faucet(address string) (string, error) {
	baseURL, err := apiBtcUrl()
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

func fetchTx(txId string) (string, error) {
	baseUrl, err := apiBtcUrl()
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

func getTxOutProof(btcTxID string) (string, error) {
	baseUrl, err := apiBtcUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx/%s/merkleblock-proof", baseUrl, btcTxID)

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

func apiBaseUrl() (string, error) {
	u, ok := os.LookupEnv("API_URL")
	if !ok {
		return "", errors.New("API_URL environment variable is not set")
	}
	return u, nil
}

func apiBtcUrl() (string, error) {
	u, ok := os.LookupEnv("API_BTC_URL")
	if !ok {
		return "", errors.New("API_URL environment variable is not set")
	}
	return u, nil
}
