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
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/block"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/pegin"
)

type NetworkType int

const (
	MainNet NetworkType = iota
	RegtestNet
)

func TestIsLiquidV1(t *testing.T) {
	fedpegScriptV1 := "745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae"
	fedpegScriptV1Bytes, err := hex.DecodeString(fedpegScriptV1)
	if err != nil {
		t.Fatal(err)
	}

	fedpegScript := "512103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b2186451ae"
	fedpegScriptBytes, err := hex.DecodeString(fedpegScript)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		script []byte
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "v1",
			args: args{
				script: fedpegScriptV1Bytes,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "not v1",
			args: args{
				script: fedpegScriptBytes,
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsLiquidV1(tt.args.script)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsLiquidV1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsLiquidV1() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateContract(t *testing.T) {
	type args struct {
		federationScript string
		scriptPubKey     string
	}
	tests := []struct {
		name     string
		args     args
		contract string
		wantErr  bool
	}{
		{
			name: "not v1",
			args: args{
				federationScript: "52210307fd375ed7cced0f50723e3e1a97bbe7ccff7318c815df4e99a59bc94dbcd819210367c4f666f18279009c941e57fab3e42653c6553e5ca092c104d1db279e328a2852ae",
				scriptPubKey:     "0014879008279c4e17fe0c61f9a84d82216cb81ddaff",
			},
			contract: "522102210dc9cd9f5925bcd256283fe28f86ffddd57a81c6be52623811873625f2fc252102035b26deb0d0f817535461b727d77bda14f0addc4c73424db9aaa838c55bb23e52ae",
			wantErr:  false,
		},
		{
			name: "v1",
			args: args{
				federationScript: "745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae",
				scriptPubKey:     "0014f66f3797fce27b9e190f9e72798203443bb33ed5",
			},
			contract: "745c87635b2103e67a1d3ca7d1dbf4c134ed3a1892f86db8235d45489961c47643c0e4916078bc21036132d580b3a0205d01873f6a1495f3ef24f6be3bad408e2c340e746cd9bc7836210260440b2b19a7ccb64b21089a542f34c7a2a08295772145acf4c06ef5c88be43e210248eb7484415570080e167f86f93fe3f7b2527c4c9848025bbf3ec7647fc218612103ca7489507aaa82a0e01af1fe9d065efd1646b8f5b664a2750639537600a78816210352049af330e49d9c1ac0f9c2b8256371ec1f2f3e9bfe77b41e541d5659e246512102af50adf71081e53d4db3764095d17a70b0520507026359bf9c0abc7c1fb99605210303d4978a7f1035feb7627f1dad0ad0ad42130641afcde19c768930ed997cd4e321030d82efb181bbeef0c81cd03f0e4f9b40f57ba6fa4f84214d65e3e18889ee2b6b210308c79da16b9b16c23a9093b68aa043d717c96e1d1b74673a847510f7ed044a48210290bfd959fed4502d367d1198da0383052d68110aa40fe61e55f3573166df1ad62103261130cbeb7efcad340d06dd90ee8c2849113e4faa02e0ac28064eb4dfb9dce62102180a7d96f8a040fd647f6b4a3981792c2fa165a784793dc15e9abbbe7edf547f21022b92fe69c0ee97d1e218ab79b72f2173686ccf7dc73989e724a9960a3835f2fb21038e9fe8af74632af44d5d57f20116ee735053eaeda787a3b7a560d9c6486dbf205f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fedpegScriptBytes, err := hex.DecodeString(tt.args.federationScript)
			if err != nil {
				t.Fatal(err)
			}

			scriptPubKeyBytes, err := hex.DecodeString(tt.args.scriptPubKey)
			if err != nil {
				t.Fatal(err)
			}

			contractBytes, err := Calculate(fedpegScriptBytes, scriptPubKeyBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("calculateContract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			gotContract := hex.EncodeToString(contractBytes)

			if gotContract != tt.contract {
				t.Errorf("calculateContract() got = %v, want %v", gotContract, tt.contract)
			}
		})
	}
}

func TestClaimPegin(t *testing.T) {
	federationScript := "52210307fd375ed7cced0f50723e3e1a97bbe7ccff7318c815df4e99a59bc94dbcd819210367c4f666f18279009c941e57fab3e42653c6553e5ca092c104d1db279e328a2852ae"
	fedpegScriptBytes, err := hex.DecodeString(federationScript)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	liquidNetwork, btcNetwork := getNetworkParams(RegtestNet)

	claimScript, err := pegin.ClaimWitnessScript(
		privateKey.PubKey().SerializeCompressed(),
		liquidNetwork,
	)

	contract, err := Calculate(
		fedpegScriptBytes,
		claimScript,
	)
	if err != nil {
		t.Fatal(err)
	}

	mainChainAddress, err := pegin.MainChainAddress(
		contract,
		btcNetwork,
		false,
		fedpegScriptBytes,
	)
	t.Log(mainChainAddress)

	//btcTxID, err := faucet(mainChainAddress)
	//if err != nil {
	//	t.Fatal(err)
	//}
	output := outputCommand("nigiri", "faucet", mainChainAddress)
	btcTxID := strings.TrimPrefix(strings.TrimSpace(string(output[:])), "txId: ")
	t.Log(btcTxID)

	time.Sleep(5 * time.Second)

	//btcTxHex, err := fetchTxHex(btcTxID)
	//if err != nil {
	//	t.Fatal(err)
	//}
	jsonOut := outputCommand("nigiri", "rpc", "gettransaction", btcTxID)
	btcTxHex := getValueByKey(jsonOut, "hex")
	t.Log(btcTxHex)
	btcBytes, err := hex.DecodeString(btcTxHex)
	if err != nil {
		t.Fatal(err)
	}

	btcTxOutProof, err := getTxOutProof(btcTxID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(btcTxOutProof)

	//arg := fmt.Sprintf("[\"%v\"]", btcTxID)
	//btcTxOutProof := outputCommand("nigiri", "rpc", "gettxoutproof", arg)
	//t.Log(strings.TrimSpace(string(btcTxOutProof[:])))
	//btcTxOutProofBytes, err := hex.DecodeString(strings.TrimSpace(string(btcTxOutProof[:])))
	//if err != nil {
	//	t.Fatal(err)
	//}

	btcTxOutProofBytes, err := hex.DecodeString(btcTxOutProof)
	if err != nil {
		t.Fatal(err)
	}

	//TODO replace with pegin.Claim
	merkleBlock, err := block.NewMerkleBlockFromBuffer(
		bytes.NewBuffer(btcTxOutProofBytes),
	)
	if err != nil {
		t.Fatal(err)
	}

	hashMerkleRoot, matchedHashes, err := merkleBlock.ExtractMatches()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(merkleBlock.BlockHeader.MerkleRoot, hashMerkleRoot.CloneBytes()) {
		t.Fatal(err)
	}

	var tx wire.MsgTx
	buff := bytes.NewReader(btcBytes)
	err = tx.BtcDecode(buff, wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		t.Fatal(err)
	}

	h := tx.TxHash()
	if len(matchedHashes) != 1 || !h.IsEqual(&matchedHashes[0]) {
		t.Fatal(err)
	}
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

func outputCommand(name string, arg ...string) []byte {
	cmd := exec.Command(name, arg...)
	bytes, _ := cmd.Output()
	return bytes
}

func getValueByKey(JSONobject []byte, key string) string {
	var data map[string]interface{}
	json.Unmarshal(JSONobject, &data)
	return data[key].(string)
}

//func faucet(address string) (string, error) {
//	baseURL, err := apiBaseUrl()
//	if err != nil {
//		return "", err
//	}
//	url := fmt.Sprintf("%s/faucet", baseURL)
//	payload := map[string]string{"address": address}
//	body, _ := json.Marshal(payload)
//
//	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
//	if err != nil {
//		return "", err
//	}
//
//	data, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		return "", err
//	}
//	if res := string(data); len(res) <= 0 || strings.Contains(res, "sendtoaddress") {
//		return "", fmt.Errorf("cannot fund address with faucet: %s", res)
//	}
//
//	respBody := map[string]string{}
//	if err := json.Unmarshal(data, &respBody); err != nil {
//		return "", err
//	}
//	return respBody["txId"], nil
//}
//
//func fetchTxHex(txId string) (string, error) {
//	baseUrl, err := apiBaseUrl()
//	if err != nil {
//		return "", err
//	}
//	url := fmt.Sprintf("%s/tx/%s/hex", baseUrl, txId)
//
//	resp, err := http.Get(url)
//	if err != nil {
//		return "", err
//	}
//
//	data, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		return "", err
//	}
//
//	return string(data), nil
//}
//
func getTxOutProof(txId string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx/%s/merkle-proof", baseUrl, txId)

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

func apiBaseUrl() (string, error) {
	u, ok := os.LookupEnv("API_URL")
	if !ok {
		return "", errors.New("API_URL environment variable is not set")
	}
	return u, nil
}
