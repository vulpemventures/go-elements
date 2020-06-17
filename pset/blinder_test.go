package pset

import (
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/transaction"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

func TestCreateBlindAndBroadcast(t *testing.T) {
	/**
	* This test attempts to broadcast a transaction composed by 1 input and 3
	* outputs. The input of the transaction will be a native segwit input, thus
	* locked by a p2wpkh script, while the outputs will be a legacy p2sh for the
	* receiver and a segwit p2wpkh for the change.
	* The 3rd output is for the fees, that in Elements side chains are explicits.
	*
	* This is intended to test that all methods provided let one to manage a
	* partial transaction from its creatation to the extraction of the final
	* tranasction so that it can be correctly broadcasted to the network and
	* included in the blockchain.
	 */

	// Generate sender random key pair.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash, _ := hex.DecodeString(utxos[0]["txid"].(string))
	txInputHash = bufferutil.ReverseBytes(txInputHash)
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	lbtc, _ := hex.DecodeString("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
	lbtc = append([]byte{0x01}, bufferutil.ReverseBytes(lbtc)...)
	receiverValue, _ := confidential.SatoshiToElementsValue(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue[:], receiverScript)

	changeScript := p2wpkh.Script
	changeValue, _ := confidential.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], changeScript)

	feeScript := []byte{}
	feeValue, _ := confidential.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	err = updater.AddInSighashType(txscript.SigHashAll, 0)
	if err != nil {
		t.Fatal(err)
	}
	witValue, _ := confidential.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue[:], p2wpkh.Script)
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	if err != nil {
		t.Fatal(err)
	}

	//blind outputs
	blindingPrivKeys := [][]byte{{}}

	blindingPubKeys := make([][]byte, 0)
	pk, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindingpubkey := pk.PubKey().SerializeCompressed()
	blindingPubKeys = append(blindingPubKeys, blindingpubkey)
	pk1, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindingpubkey1 := pk1.PubKey().SerializeCompressed()
	blindingPubKeys = append(blindingPubKeys, blindingpubkey1)

	blinder, err := NewBlinder(
		p,
		blindingPrivKeys,
		blindingPubKeys,
		nil,
		nil)
	if err != nil {
		t.Fatal(err)
	}
	err = blinder.BlindTransaction()
	if err != nil {
		t.Fatal(err)
	}

	// The signing of the input is done by retrieving the proper hash of the serialization
	// of the transaction (the BIP-0143 segwit version in this case) directly from the pset's
	// UnsignedTx.
	// NOTE: to correctly sign an utxo locked by a p2wpkh script, we must use the legacy pubkey script
	// when serializing the transaction.
	legacyScript := append(append([]byte{0x76, 0xa9, 0x14}, p2wpkh.Hash...), []byte{0x88, 0xac}...)
	witHash := updater.Upsbt.UnsignedTx.HashForWitnessV0(0, legacyScript, witValue[:], txscript.SigHashAll)
	sig, err := privkey.Sign(witHash[:])
	if err != nil {
		t.Fatal(err)
	}

	sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))

	// Update the pset adding the input signature script and the pubkey.
	_, err = updater.Sign(0, sigWithHashType, pubkey.SerializeCompressed(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Finalize the partial transaction.
	p = updater.Upsbt
	err = FinalizeAll(p)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the final signed transaction from the Pset wrapper.
	finalTx, err := Extract(p)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize the transaction and try to broadcast.
	txHex, err := finalTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}
	txid, err := broadcast(txHex)
	if err != nil {
		t.Fatal(err)
	}

	if len(txid) <= 0 {
		t.Fatal("Expected transaction to be broadcasted")
	}
}

func TestCreateBlindSignBroadcastWithConfidentialInput(t *testing.T) {
	/**
	* This test attempts to broadcast a transaction composed by 1
	confidential input 	and 3 * outputs.
	The input of the transaction will be a native segwit input, thus
	* locked by a p2wpkh script, while the outputs will be a legacy p2sh for the
	* receiver and a segwit p2wpkh for the change.
	* The 3rd output is for the fees, that in Elements side chains are explicits.
	*
	* This is intended to test that all methods provided let one to manage a
	* partial transaction from its creatation to the extraction of the final
	* tranasction so that it can be correctly broadcasted to the network and
	* included in the blockchain.
	*/

	// Generate sender random key pair.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()

	blindingPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindingPublicKey := blindingPrivateKey.PubKey()

	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)

	confidentialAddress, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(confidentialAddress)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(confidentialAddress)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash, _ := hex.DecodeString(utxos[0]["txid"].(string))
	txInputHash = bufferutil.ReverseBytes(txInputHash)
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	lbtc, _ := hex.DecodeString("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
	lbtc = append([]byte{0x01}, bufferutil.ReverseBytes(lbtc)...)
	receiverValue, _ := confidential.SatoshiToElementsValue(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue[:], receiverScript)

	changeScript := p2wpkh.Script
	changeValue, _ := confidential.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], changeScript)

	feeScript := []byte{}
	feeValue, _ := confidential.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	err = updater.AddInSighashType(txscript.SigHashAll, 0)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := fetchTx(utxos[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}

	trx, err := transaction.NewTxFromHex(string(tx))
	if err != nil {
		t.Fatal(err)
	}

	valueCommitment, err := hex.DecodeString(utxos[0]["valuecommitment"].(string))
	if err != nil {
		t.Fatal(err)
	}
	assetCommitment, err := hex.DecodeString(utxos[0]["assetcommitment"].(string))
	if err != nil {
		t.Fatal(err)
	}
	witnessUtxo := &transaction.TxOutput{
		Asset:           assetCommitment,
		Value:           valueCommitment,
		Script:          p2wpkh.Script,
		Nonce:           trx.Outputs[txInputIndex].Nonce,
		RangeProof:      trx.Outputs[txInputIndex].RangeProof,
		SurjectionProof: trx.Outputs[txInputIndex].SurjectionProof,
	}
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	if err != nil {
		t.Fatal(err)
	}
	//blind outputs
	blindingPrivKeys := [][]byte{blindingPrivateKey.Serialize()}

	blindingPubKeys := make([][]byte, 0)
	pk, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindingpubkey := pk.PubKey().SerializeCompressed()
	blindingPubKeys = append(blindingPubKeys, blindingpubkey)
	pk1, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindingpubkey1 := pk1.PubKey().SerializeCompressed()
	blindingPubKeys = append(blindingPubKeys, blindingpubkey1)

	blinder, err := NewBlinder(
		p,
		blindingPrivKeys,
		blindingPubKeys,
		nil,
		nil)
	if err != nil {
		t.Fatal(err)
	}
	err = blinder.BlindTransaction()
	if err != nil {
		t.Fatal(err)
	}

	// The signing of the input is done by retrieving the proper hash of the
	//serialization of the transaction (the BIP-0143 segwit version in this
	//case) directly from the pset's UnsignedTx.
	//NOTE: to correctly sign an utxo locked by a p2wpkh script,
	//we must use the legacy pubkey script when serializing the transaction.
	legacyScript := append(
		append(
			[]byte{0x76, 0xa9, 0x14},
			p2wpkh.Hash...,
		),
		[]byte{0x88, 0xac}...,
	)
	witHash := updater.Upsbt.UnsignedTx.HashForWitnessV0(
		0,
		legacyScript,
		witnessUtxo.Value,
		txscript.SigHashAll,
	)
	sig, err := privkey.Sign(witHash[:])
	if err != nil {
		t.Fatal(err)
	}

	sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))

	// Update the pset adding the input signature script and the pubkey.
	_, err = updater.Sign(0, sigWithHashType, pubkey.SerializeCompressed(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Finalize the partial transaction.
	p = updater.Upsbt
	err = FinalizeAll(p)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the final signed transaction from the Pset wrapper.
	finalTx, err := Extract(p)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize the transaction and try to broadcast.
	txHex, err := finalTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}
	txid, err := broadcast(txHex)
	if err != nil {
		t.Fatal(err)
	}

	if len(txid) <= 0 {
		t.Fatal("Expected transaction to be broadcasted")
	}
}

func fetchTx(txId string) ([]byte, error) {
	baseUrl, ok := os.LookupEnv("API_URL")
	if !ok {
		return nil, errors.New("API_URL environment variable is not set")
	}
	url := baseUrl + "/tx/" + txId + "/hex"
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
