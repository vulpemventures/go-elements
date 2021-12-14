package psetv2test

import (
	"testing"
	"time"

	"github.com/vulpemventures/go-elements/confidential"

	"github.com/vulpemventures/go-elements/psetv2"

	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/transaction"
)

func TestBroadcastBlindedTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	creatorRole, err := psetv2.NewCreatorRole(nil)
	if err != nil {
		t.Fatal(err)
	}

	pset, err := creatorRole.Create()
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript := h2b("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	inputArgs := []psetv2.InputArg{
		{
			TimeLock: nil,
			TxInput:  *txInput,
		},
	}
	outputBlindingPrivKey1, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	outputBlindingPubKey1 := outputBlindingPrivKey1.PubKey().SerializeCompressed()

	outputBlindingPrivKey2, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	outputBlindingPubKey2 := outputBlindingPrivKey2.PubKey().SerializeCompressed()

	outputArgs := []psetv2.OutputArg{
		{
			BlinderIndex:   0,
			BlindingPubKey: outputBlindingPubKey1,
			TxOutput:       *receiverOutput,
		},
		{
			BlinderIndex:   0,
			BlindingPubKey: outputBlindingPubKey2,
			TxOutput:       *changeOutput,
		},
	}
	constructor, err := psetv2.NewConstructorRole(
		pset,
		inputArgs,
		outputArgs,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = constructor.Construct(); err != nil {
		t.Fatal(err)
	}

	updaterRole, err := psetv2.NewUpdaterRole(pset)
	if err != nil {
		t.Fatal(err)
	}

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:           assetCommitment,
		Value:           valueCommitment,
		Script:          p2wpkh.WitnessScript,
		Nonce:           prevTx.Outputs[txInputIndex].Nonce,
		RangeProof:      prevTx.Outputs[txInputIndex].RangeProof,
		SurjectionProof: prevTx.Outputs[txInputIndex].SurjectionProof,
	}
	if err := updaterRole.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	blinderSvc := confidential.NewBlinder()
	prevOutUnBlindingInfos := []psetv2.UnBlindingInfo{
		{
			OutIndex:              0,
			OutPrivateBlindingKey: blindingPrivateKey.Serialize(),
		},
	}
	blinderRole, err := psetv2.NewBlinderRole(
		pset,
		blinderSvc,
		prevOutUnBlindingInfos,
		psetv2.IssuanceBlindingPrivateKeys{},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := blinderRole.Blind(); err != nil {
		t.Fatal(err)
	}

	outUnblindingInfo := []psetv2.UnBlindingInfo{
		{
			OutIndex:              0,
			OutPrivateBlindingKey: outputBlindingPrivKey1.Serialize(),
		},
		{
			OutIndex:              1,
			OutPrivateBlindingKey: outputBlindingPrivKey2.Serialize(),
		},
	}
	if !blinderRole.Verify(outUnblindingInfo) {
		t.Fatal("blinding invalid")
	}

	if err := addFeesToTransaction(pset, 500); err != nil {
		t.Fatal(err)
	}

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(pset, prvKeys, scripts, true, nil, blinderSvc); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(pset, blinderSvc); err != nil {
		t.Fatal(err)
	}
}
