package taproot_test

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

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/louisinger/btcd/btcec/v2"
	"github.com/louisinger/btcd/btcec/v2/schnorr"
	"github.com/louisinger/btcd/btcec/v2/schnorr/musig2"
	"github.com/stretchr/testify/assert"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/pset"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

func TestKeyPathSpend(t *testing.T) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	blindingKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	taprootPay, err := payment.FromTaprootScriptTreeHash(privateKey.PubKey(), nil, &network.Regtest, blindingKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	addr, err := taprootPay.ConfidentialTaprootAddress()
	if err != nil {
		t.Fatal(err)
	}

	taprootScript, err := address.ToOutputScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	txID, err := faucet(addr)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)

	faucetTx, err := fetchTx(txID)
	if err != nil {
		t.Fatal(err)
	}

	var utxo *transaction.TxOutput
	var vout int
	for index, out := range faucetTx.Outputs {
		if bytes.Equal(out.Script, taprootScript) {
			utxo = out
			vout = index
			break
		}
	}

	if utxo == nil {
		t.Fatal("could not find utxo")
	}

	lbtc, _ := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	)
	lbtc = append([]byte{0x01}, elementsutil.ReverseBytes(lbtc)...)

	hash := faucetTx.TxHash()
	txInput := transaction.NewTxInput(hash[:], uint32(vout))

	receiverValue, _ := elementsutil.ValueToBytes(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue[:], receiverScript)

	changeValue, _ := elementsutil.ValueToBytes(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], taprootScript) // address reuse here (change = input's script)

	feeScript := []byte{}
	feeValue, _ := elementsutil.ValueToBytes(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)

	p, _ := pset.New([]*transaction.TxInput{txInput}, []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}, 2, 0)

	updater, err := pset.NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	updater.AddInSighashType(txscript.SigHashDefault, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater.AddInWitnessUtxo(utxo, 0)

	blindDataLike := make([]pset.BlindingDataLike, 1)
	blindDataLike[0] = pset.PrivateBlindingKey(blindingKey.Serialize())

	outputPubKeyByIndex := make(map[int][]byte)
	outputPubKeyByIndex[0] = blindingKey.PubKey().SerializeCompressed()
	outputPubKeyByIndex[1] = blindingKey.PubKey().SerializeCompressed()

	blinder, _ := pset.NewBlinder(
		p,
		blindDataLike,
		outputPubKeyByIndex,
		nil,
		nil,
	)

	err = blinder.Blind()
	if err != nil {
		t.Fatal(err)
	}

	unsignedTx := p.UnsignedTx
	// Sign step

	genesisBlockhash, _ := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")

	sighash := unsignedTx.HashForWitnessV1(
		0,
		[][]byte{
			utxo.Script,
		},
		[][]byte{
			utxo.Asset,
		},
		[][]byte{
			utxo.Value,
		},
		txscript.SigHashDefault,
		genesisBlockhash,
		nil,
		nil,
	)

	tweakedPrivKey := taproot.TweakTaprootPrivKey(privateKey, []byte{})

	sig, err := schnorr.Sign(tweakedPrivKey, sighash[:])
	if err != nil {
		t.Fatal(err)
	}

	unsignedTx.Inputs[0].Witness = transaction.TxWitness{
		sig.Serialize(),
	}

	signed, err := unsignedTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}

	_, err = broadcast(signed)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, txID)
}

func TestKeyPathMusig2(t *testing.T) {
	bob, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	bobNonces, err := musig2.GenNonces(musig2.WithPublicKey(bob.PubKey()))
	if err != nil {
		t.Fatal(err)
	}

	alice, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	aliceNonces, err := musig2.GenNonces(musig2.WithPublicKey(alice.PubKey()))
	if err != nil {
		t.Fatal(err)
	}

	keys := []*btcec.PublicKey{alice.PubKey(), bob.PubKey()}

	aggregateKey, _, _, err := musig2.AggregateKeys(keys, true, musig2.WithTaprootKeyTweak([]byte{}), musig2.WithTapTweakTag(taproot.TagTapTweakElements))
	if err != nil {
		t.Fatal(err)
	}

	blindingKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	taprootPay, err := payment.FromTweakedKey(aggregateKey.FinalKey, &network.Regtest, blindingKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	addr, err := taprootPay.ConfidentialTaprootAddress()
	if err != nil {
		t.Fatal(err)
	}

	taprootScript, err := address.ToOutputScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	txID, err := faucet(addr)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)

	faucetTx, err := fetchTx(txID)
	if err != nil {
		t.Fatal(err)
	}

	var utxo *transaction.TxOutput
	var vout int
	for index, out := range faucetTx.Outputs {
		if bytes.Equal(out.Script, taprootScript) {
			utxo = out
			vout = index
			break
		}
	}

	if utxo == nil {
		t.Fatal("could not find utxo")
	}

	lbtc, _ := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	)
	lbtc = append([]byte{0x01}, elementsutil.ReverseBytes(lbtc)...)

	hash := faucetTx.TxHash()
	txInput := transaction.NewTxInput(hash[:], uint32(vout))

	receiverValue, _ := elementsutil.ValueToBytes(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue[:], receiverScript)

	changeValue, _ := elementsutil.ValueToBytes(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], taprootScript) // address reuse here (change = input's script)

	feeScript := []byte{}
	feeValue, _ := elementsutil.ValueToBytes(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)

	p, _ := pset.New([]*transaction.TxInput{txInput}, []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}, 2, 0)

	updater, err := pset.NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	updater.AddInSighashType(txscript.SigHashDefault, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater.AddInWitnessUtxo(utxo, 0)

	blindDataLike := make([]pset.BlindingDataLike, 1)
	blindDataLike[0] = pset.PrivateBlindingKey(blindingKey.Serialize())

	outputPubKeyByIndex := make(map[int][]byte)
	outputPubKeyByIndex[0] = blindingKey.PubKey().SerializeCompressed()
	outputPubKeyByIndex[1] = blindingKey.PubKey().SerializeCompressed()

	blinder, _ := pset.NewBlinder(
		p,
		blindDataLike,
		outputPubKeyByIndex,
		nil,
		nil,
	)

	err = blinder.Blind()
	if err != nil {
		t.Fatal(err)
	}

	unsignedTx := p.UnsignedTx
	// Sign step

	genesisBlockhash, _ := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")

	sighash := unsignedTx.HashForWitnessV1(
		0,
		[][]byte{
			utxo.Script,
		},
		[][]byte{
			utxo.Asset,
		},
		[][]byte{
			utxo.Value,
		},
		txscript.SigHashDefault,
		genesisBlockhash,
		nil,
		nil,
	)

	aggregatedNonces, err := musig2.AggregateNonces([][66]byte{aliceNonces.PubNonce, bobNonces.PubNonce})
	if err != nil {
		t.Fatal(err)
	}

	keysWithSecNonce := make([]struct {
		key   *secp256k1.PrivateKey
		nonce [97]byte
	}, 2)

	keysWithSecNonce[0].key = alice
	keysWithSecNonce[0].nonce = aliceNonces.SecNonce
	keysWithSecNonce[1].key = bob
	keysWithSecNonce[1].nonce = bobNonces.SecNonce

	sigs := make([]*musig2.PartialSignature, 2)
	for i, keyWithNonce := range keysWithSecNonce {
		sigs[i], err = musig2.Sign(keyWithNonce.nonce, keyWithNonce.key, aggregatedNonces, []*secp256k1.PublicKey{alice.PubKey(), bob.PubKey()}, sighash, musig2.WithTaprootSignTweak([]byte{}), musig2.WithTaprootSignTweakTag(taproot.TagTapTweakElements))
		if err != nil {
			t.Fatal(err)
		}
	}

	sig := musig2.CombineSigs(sigs[0].R, sigs, musig2.WithTapTweakTagCombine(taproot.TagTapTweakElements), musig2.WithTaprootTweakedCombine(sighash, keys, []byte{}, true))

	if !sig.Verify(sighash[:], aggregateKey.FinalKey) {
		t.Fatal("signature is not valid")
	}

	unsignedTx.Inputs[0].Witness = transaction.TxWitness{
		sig.Serialize(),
	}

	signed, err := unsignedTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}

	_, err = broadcast(signed)
	if err != nil {
		t.Log(signed)
		t.Fatal(err)
	}

	assert.NotEmpty(t, txID)
}

func TestTapscriptSpend(t *testing.T) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	blindingKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	checksigSchnorrScript, err := txscript.NewScriptBuilder().AddData(schnorr.SerializePubKey(privateKey.PubKey())).AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		t.Fatal(err)
	}

	tree := taproot.AssembleTaprootScriptTree(taproot.NewBaseTapElementsLeaf(checksigSchnorrScript))

	taprootPay, err := payment.FromTaprootScriptTree(privateKey.PubKey(), tree, &network.Regtest, blindingKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	addr, err := taprootPay.ConfidentialTaprootAddress()
	if err != nil {
		t.Fatal(err)
	}

	txID, err := faucet(addr)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)

	faucetTx, err := fetchTx(txID)
	if err != nil {
		t.Fatal(err)
	}

	var utxo *transaction.TxOutput
	var vout int
	for index, out := range faucetTx.Outputs {
		if bytes.Equal(out.Script, taprootPay.Script) {
			utxo = out
			vout = index
			break
		}
	}

	if utxo == nil {
		t.Fatal("could not find utxo")
	}

	lbtc, _ := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	)
	lbtc = append([]byte{0x01}, elementsutil.ReverseBytes(lbtc)...)

	hash := faucetTx.TxHash()
	txInput := transaction.NewTxInput(hash[:], uint32(vout))

	receiverValue, _ := elementsutil.ValueToBytes(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue[:], receiverScript)

	changeValue, _ := elementsutil.ValueToBytes(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], taprootPay.Script) // address reuse here (change = input's script)

	feeScript := []byte{}
	feeValue, _ := elementsutil.ValueToBytes(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)

	p, _ := pset.New([]*transaction.TxInput{txInput}, []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}, 2, 0)

	updater, err := pset.NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	updater.AddInSighashType(txscript.SigHashDefault, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater.AddInWitnessUtxo(utxo, 0)

	blindDataLike := make([]pset.BlindingDataLike, 1)
	blindDataLike[0] = pset.PrivateBlindingKey(blindingKey.Serialize())

	outputPubKeyByIndex := make(map[int][]byte)
	outputPubKeyByIndex[0] = blindingKey.PubKey().SerializeCompressed()
	outputPubKeyByIndex[1] = blindingKey.PubKey().SerializeCompressed()

	blinder, _ := pset.NewBlinder(
		p,
		blindDataLike,
		outputPubKeyByIndex,
		nil,
		nil,
	)

	err = blinder.Blind()
	if err != nil {
		t.Fatal(err)
	}

	unsignedTx := p.UnsignedTx

	// Sign step
	genesisBlockhash, _ := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")

	leafProof := tree.LeafMerkleProofs[0]
	leafHash := leafProof.TapHash()

	sighash := unsignedTx.HashForWitnessV1(
		0,
		[][]byte{
			utxo.Script,
		},
		[][]byte{
			utxo.Asset,
		},
		[][]byte{
			utxo.Value,
		},
		txscript.SigHashDefault,
		genesisBlockhash,
		&leafHash,
		nil,
	)

	sig, err := schnorr.Sign(privateKey, sighash[:])
	if err != nil {
		t.Fatal(err)
	}

	controlBlock := leafProof.ToControlBlock(privateKey.PubKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	unsignedTx.Inputs[0].Witness = transaction.TxWitness{
		sig.Serialize(),
		leafProof.Script,
		controlBlockBytes,
	}

	signed, err := unsignedTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}

	_, err = broadcast(signed)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, txID)
}

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

func fetchTx(txId string) (*transaction.Transaction, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/tx/%s/hex", baseUrl, txId)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	hex := string(data)
	return transaction.NewTxFromHex(hex)
}
