package psetv2_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"

	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

var (
	sighashAll = txscript.SigHashAll
)

/*
*	The fixtures for this test have been generated with Elements CLI and
*	demonstrate that this package is able to serialize a partial transaction
* compliant with the Elements implementation.
 */
func TestRoundTrip(t *testing.T) {
	file, _ := ioutil.ReadFile("testdata/roundtrip.json")
	var fixtures map[string]interface{}
	json.Unmarshal(file, &fixtures)

	invalid := fixtures["invalid"].([]interface{})
	t.Run("invalid", func(t *testing.T) {
		for _, v := range invalid {
			tt := v.(map[string]interface{})
			t.Run(tt["name"].(string), func(t *testing.T) {
				psetBase64 := tt["base64"].(string)
				ptx, err := psetv2.NewPsetFromBase64(psetBase64)
				require.EqualError(t, err, tt["expectedError"].(string))
				require.Nil(t, ptx)
			})
		}
	})

	valid := fixtures["valid"].([]interface{})
	t.Run("valid", func(t *testing.T) {
		for _, v := range valid {
			tt := v.(map[string]interface{})
			t.Run(tt["name"].(string), func(t *testing.T) {
				psetBase64 := tt["base64"].(string)

				ptx, err := psetv2.NewPsetFromBase64(psetBase64)
				require.NoError(t, err)

				ptxBase64, err := ptx.ToBase64()
				require.NoError(t, err)
				a, _ := base64.StdEncoding.DecodeString(psetBase64)
				b, _ := base64.StdEncoding.DecodeString(ptxBase64)
				require.Equal(t, b2h(a), b2h(b))
			})
		}
	})
}

func TestBroadcastUnblindedTx(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 60000000,
			Script: h2b("76a914f5b9864394bb5bc62691750cb32c9cbe522f0c3f88ac"),
		},
		{
			Asset:  lbtc,
			Amount: 39999500,
			Script: p2wpkh.WitnessScript,
		},
		{
			Asset:  lbtc,
			Amount: 500,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	asset, _ := elementsutil.AssetHashToBytes(utxos[0]["asset"].(string))
	value, _ := elementsutil.ValueToBytes(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(asset, value, p2wpkh.WitnessScript)
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastUnblindedIssuanceTx(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 99999500,
			Script: p2wpkh.WitnessScript,
		},
		{
			Asset:  lbtc,
			Amount: 500,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	asset, _ := elementsutil.AssetHashToBytes(utxos[0]["asset"].(string))
	value, _ := elementsutil.ValueToBytes(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(asset, value, p2wpkh.WitnessScript)
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)

	err = updater.AddInIssuance(0, psetv2.AddInIssuanceArgs{
		AssetAmount:  1000,
		TokenAmount:  1,
		AssetAddress: address,
		TokenAddress: address,
	})
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 60000000,
			Script: h2b("76a914f5b9864394bb5bc62691750cb32c9cbe522f0c3f88ac"),
		},
		{
			Asset:        lbtc,
			Amount:       39999500,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: p2wpkh.WitnessScript,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, []uint32{1})
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 500,
		},
	})
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedTxWithDummyConfidentialOutputs(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 60000000,
			Script: h2b("76a914f5b9864394bb5bc62691750cb32c9cbe522f0c3f88ac"),
		},
		{
			Asset:  lbtc,
			Amount: 39999500,
			Script: p2wpkh.WitnessScript,
		},
		{
			Asset:       lbtc,
			Amount:      0,
			Script:      []byte{txscript.OP_RETURN},
			BlindingKey: blindingPublicKey.SerializeCompressed(),
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: p2wpkh.WitnessScript,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, []uint32{2})
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 500,
		},
	})
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastUnblindedIssuanceTxWithBlindedOutputs(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       99999000,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: p2wpkh.WitnessScript,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	err = updater.AddInIssuance(0, psetv2.AddInIssuanceArgs{
		AssetAmount:     1000,
		TokenAmount:     1,
		AssetAddress:    address,
		TokenAddress:    address,
		BlindedIssuance: false,
	})
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedIssuanceTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       99999000,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: p2wpkh.WitnessScript,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	err = updater.AddInIssuance(0, psetv2.AddInIssuanceArgs{
		AssetAmount:     1000,
		TokenAmount:     1,
		AssetAddress:    address,
		TokenAddress:    address,
		BlindedIssuance: true,
	})
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(ptx, ownedInputs, zkpValidator, zkpGenerator)
	require.NoError(t, err)

	issuanceKeysByIndex := map[uint32][]byte{
		0: blindingPrivateKey.Serialize(),
	}
	inIssuanceBlindingArgs, err := zkpGenerator.BlindIssuances(ptx, issuanceKeysByIndex)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(inIssuanceBlindingArgs, outBlindingArgs)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedIssuanceTxWithConfAndUnconfAddresses(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()
	unconfAddress, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       99999000,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: p2wpkh.WitnessScript,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	err = updater.AddInIssuance(0, psetv2.AddInIssuanceArgs{
		AssetAmount:     1000,
		TokenAmount:     1,
		AssetAddress:    address,
		TokenAddress:    unconfAddress,
		BlindedIssuance: true,
	})
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(ptx, ownedInputs, zkpValidator, zkpGenerator)
	require.NoError(t, err)

	issuanceKeysByIndex := map[uint32][]byte{
		0: blindingPrivateKey.Serialize(),
	}
	inIssuanceBlindingArgs, err := zkpGenerator.BlindIssuances(ptx, issuanceKeysByIndex)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(inIssuanceBlindingArgs, outBlindingArgs)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedReissuanceTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       99999000,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: p2wpkh.WitnessScript,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	err = updater.AddInIssuance(0, psetv2.AddInIssuanceArgs{
		AssetAmount:     1000,
		TokenAmount:     1,
		AssetAddress:    address,
		TokenAddress:    address,
		BlindedIssuance: true,
	})
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(ptx, ownedInputs, zkpValidator, zkpGenerator)
	require.NoError(t, err)

	issuanceKeysByIndex := map[uint32][]byte{
		0: blindingPrivateKey.Serialize(),
	}
	inIssuanceBlindingArgs, err := zkpGenerator.BlindIssuances(ptx, issuanceKeysByIndex)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(inIssuanceBlindingArgs, outBlindingArgs)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)

	issuanceTx, err := ptx.UnsignedTx()
	require.NoError(t, err)

	// Reissue.
	reissuanceInputs := []psetv2.InputArgs{
		{
			TxIndex: 0,
			Txid:    issuanceTx.TxHash().String(),
		},
		{
			Txid:    issuanceTx.TxHash().String(),
			TxIndex: 3,
		},
	}

	reissuanceOutputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       99998000,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	reissuancePtx, err := psetv2.New(reissuanceInputs, reissuanceOutputArgs, nil)
	require.NoError(t, err)

	updater, err = psetv2.NewUpdater(reissuancePtx)
	require.NoError(t, err)

	err = updater.AddInWitnessUtxo(0, issuanceTx.Outputs[0])
	require.NoError(t, err)

	err = updater.AddInUtxoRangeProof(0, issuanceTx.Outputs[0].RangeProof)
	require.NoError(t, err)

	err = updater.AddInWitnessUtxo(1, issuanceTx.Outputs[3])
	require.NoError(t, err)

	err = updater.AddInUtxoRangeProof(1, issuanceTx.Outputs[3].RangeProof)
	require.NoError(t, err)

	entropy, err := transaction.ComputeEntropy(issuanceTx.Inputs[0].Hash, issuanceTx.Inputs[0].Index, issuanceTx.Inputs[0].Issuance.AssetEntropy)
	require.NoError(t, err)

	err = updater.AddInReissuance(1, psetv2.AddInReissuanceArgs{
		TokenPrevOutBlinder: outBlindingArgs[2].AssetBlinder,
		Entropy:             hex.EncodeToString(elementsutil.ReverseBytes(entropy)),
		AssetAmount:         1000,
		AssetAddress:        "el1qq0k562f2kgxruw6z5gztxhxegls8mjlxxccmuham3dhxu8r207pkl3nuydlvy22g00nx6s47xudtm3y0sw32jwpjsd3vps070",
		TokenAmount:         1,
		TokenAddress:        "el1qq0k562f2kgxruw6z5gztxhxegls8mjlxxccmuham3dhxu8r207pkl3nuydlvy22g00nx6s47xudtm3y0sw32jwpjsd3vps070",
	})
	require.NoError(t, err)

	zkpGenerator = confidential.NewZKPGeneratorFromBlindingKeys([][]byte{blindingPrivateKey.Serialize()}, nil)
	require.NoError(t, err)

	ownedInputs, err = zkpGenerator.UnblindInputs(reissuancePtx, nil)
	require.NoError(t, err)

	reissuanceKeysByIndex := map[uint32][]byte{
		1: blindingPrivateKey.Serialize(),
	}
	inReissuanceBlindingArgs, err := zkpGenerator.BlindIssuances(reissuancePtx, reissuanceKeysByIndex)
	require.NoError(t, err)

	outBlindingArgsReissuance, err := zkpGenerator.BlindOutputs(reissuancePtx, nil)
	require.NoError(t, err)

	blinder, err = psetv2.NewBlinder(reissuancePtx, ownedInputs, zkpValidator, zkpGenerator)
	require.NoError(t, err)

	err = blinder.BlindLast(inReissuanceBlindingArgs, outBlindingArgsReissuance)
	require.NoError(t, err)

	prvKeys = append(prvKeys, privkey)
	scripts = [][]byte{p2wpkh.Script, p2wpkh.Script}
	err = signTransaction(reissuancePtx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(reissuancePtx)
	require.NoError(t, err)
}

func TestBroadcastBlindedReissuanceTxWithUnconfidentialTokenAddress(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()
	unconfAddress, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       99999000,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: p2wpkh.WitnessScript,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	err = updater.AddInIssuance(0, psetv2.AddInIssuanceArgs{
		AssetAmount:     1000,
		TokenAmount:     1,
		AssetAddress:    address,
		TokenAddress:    address,
		BlindedIssuance: true,
	})
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(ptx, ownedInputs, zkpValidator, zkpGenerator)
	require.NoError(t, err)

	issuanceKeysByIndex := map[uint32][]byte{
		0: blindingPrivateKey.Serialize(),
	}
	inIssuanceBlindingArgs, err := zkpGenerator.BlindIssuances(ptx, issuanceKeysByIndex)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(inIssuanceBlindingArgs, outBlindingArgs)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)

	issuanceTx, err := ptx.UnsignedTx()
	require.NoError(t, err)

	// Reissue.
	reissuanceInputs := []psetv2.InputArgs{
		{
			TxIndex: 0,
			Txid:    issuanceTx.TxHash().String(),
		},
		{
			Txid:    issuanceTx.TxHash().String(),
			TxIndex: 3,
		},
	}

	reissuanceOutputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       99998000,
			Script:       p2wpkh.WitnessScript,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	reissuancePtx, err := psetv2.New(reissuanceInputs, reissuanceOutputArgs, nil)
	require.NoError(t, err)

	updater, err = psetv2.NewUpdater(reissuancePtx)
	require.NoError(t, err)

	err = updater.AddInWitnessUtxo(0, issuanceTx.Outputs[0])
	require.NoError(t, err)

	err = updater.AddInUtxoRangeProof(0, issuanceTx.Outputs[0].RangeProof)
	require.NoError(t, err)

	err = updater.AddInWitnessUtxo(1, issuanceTx.Outputs[3])
	require.NoError(t, err)

	err = updater.AddInUtxoRangeProof(1, issuanceTx.Outputs[3].RangeProof)
	require.NoError(t, err)

	entropy, err := transaction.ComputeEntropy(issuanceTx.Inputs[0].Hash, issuanceTx.Inputs[0].Index, issuanceTx.Inputs[0].Issuance.AssetEntropy)
	require.NoError(t, err)

	err = updater.AddInReissuance(1, psetv2.AddInReissuanceArgs{
		TokenPrevOutBlinder: outBlindingArgs[2].AssetBlinder,
		Entropy:             hex.EncodeToString(elementsutil.ReverseBytes(entropy)),
		AssetAmount:         1000,
		AssetAddress:        "el1qq0k562f2kgxruw6z5gztxhxegls8mjlxxccmuham3dhxu8r207pkl3nuydlvy22g00nx6s47xudtm3y0sw32jwpjsd3vps070",
		TokenAmount:         1,
		TokenAddress:        unconfAddress,
	})
	require.NoError(t, err)

	zkpGenerator = confidential.NewZKPGeneratorFromBlindingKeys([][]byte{blindingPrivateKey.Serialize()}, nil)
	require.NoError(t, err)

	ownedInputs, err = zkpGenerator.UnblindInputs(reissuancePtx, nil)
	require.NoError(t, err)

	reissuanceKeysByIndex := map[uint32][]byte{
		1: blindingPrivateKey.Serialize(),
	}
	inReissuanceBlindingArgs, err := zkpGenerator.BlindIssuances(reissuancePtx, reissuanceKeysByIndex)
	require.NoError(t, err)

	outBlindingArgsReissuance, err := zkpGenerator.BlindOutputs(reissuancePtx, nil)
	require.NoError(t, err)

	blinder, err = psetv2.NewBlinder(reissuancePtx, ownedInputs, zkpValidator, zkpGenerator)
	require.NoError(t, err)

	err = blinder.BlindLast(inReissuanceBlindingArgs, outBlindingArgsReissuance)
	require.NoError(t, err)

	prvKeys = append(prvKeys, privkey)
	scripts = [][]byte{p2wpkh.Script, p2wpkh.Script}
	err = signTransaction(reissuancePtx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(reissuancePtx)
	require.NoError(t, err)
}

// This test shows how 2 parties can create a confiendital swap transaction
// by sharing the blinding private keys.
func TestBroadcastBlindedSwapTx(t *testing.T) {
	aliceBlindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	alicePrivkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	aliceBlindingPublicKey := aliceBlindingPrivateKey.PubKey()
	alicePubkey := alicePrivkey.PubKey()
	aliceP2wpkh := payment.FromPublicKey(alicePubkey, &network.Regtest, aliceBlindingPublicKey)
	aliceAddress, _ := aliceP2wpkh.ConfidentialWitnessPubKeyHash()

	bobBlindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bobPrivkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	bobBlindingPublicKey := bobBlindingPrivateKey.PubKey()
	bobPubkey := bobPrivkey.PubKey()
	bobP2wpkh := payment.FromPublicKey(bobPubkey, &network.Regtest, bobBlindingPublicKey)
	bobAddress, _ := bobP2wpkh.ConfidentialWitnessPubKeyHash()

	// Send LBTC funds to alice's address.
	_, err = faucet(aliceAddress)
	require.NoError(t, err)

	// Send USDT funds to bob's address.
	_, usdt, err := mint(bobAddress, 1, "", "")
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve alice's utxos.
	aliceUtxos, err := unspents(aliceAddress)
	require.NoError(t, err)

	// Retrieve bob's utxos.
	bobUtxos, err := unspents(bobAddress)
	require.NoError(t, err)

	alicePrevoutIndex := uint32(aliceUtxos[0]["vout"].(float64))
	alicePrevoutTxid := aliceUtxos[0]["txid"].(string)

	// Alice creates the transaction with her inputs and expected outputs.
	aliceInputArgs := []psetv2.InputArgs{
		{
			TxIndex: alicePrevoutIndex,
			Txid:    alicePrevoutTxid,
		},
	}

	aliceOutputArgs := []psetv2.OutputArgs{
		{
			Asset:        usdt,
			Amount:       50000000,
			Script:       aliceP2wpkh.WitnessScript,
			BlindingKey:  aliceBlindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:        lbtc,
			Amount:       49999000,
			Script:       aliceP2wpkh.WitnessScript,
			BlindingKey:  aliceBlindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
		{
			Asset:  lbtc,
			Amount: 1000,
		},
	}

	ptx, err := psetv2.New(aliceInputArgs, aliceOutputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	alicePrevTxHex, err := fetchTx(aliceUtxos[0]["txid"].(string))
	require.NoError(t, err)

	alicePrevTx, _ := transaction.NewTxFromHex(alicePrevTxHex)
	aliceAssetCommitment := h2b(aliceUtxos[0]["assetcommitment"].(string))
	aliceValueCommitment := h2b(aliceUtxos[0]["valuecommitment"].(string))
	aliceWitnessUtxo := &transaction.TxOutput{
		Asset:  aliceAssetCommitment,
		Value:  aliceValueCommitment,
		Script: aliceP2wpkh.WitnessScript,
		Nonce:  alicePrevTx.Outputs[alicePrevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, aliceWitnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, alicePrevTx.Outputs[alicePrevoutIndex].RangeProof)
	require.NoError(t, err)

	// Now it's bob's turn to add his input and outputs.
	bobPrevoutIndex := uint32(bobUtxos[0]["vout"].(float64))
	bobPrevoutTxid := bobUtxos[0]["txid"].(string)

	bobInputArgs := []psetv2.InputArgs{
		{
			Txid:    bobPrevoutTxid,
			TxIndex: bobPrevoutIndex,
		},
	}

	err = updater.AddInputs(bobInputArgs)
	require.NoError(t, err)

	bobOutputBlinderIndex := uint32(1)
	bobOutputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       50000000,
			Script:       bobP2wpkh.WitnessScript,
			BlindingKey:  bobBlindingPublicKey.SerializeCompressed(),
			BlinderIndex: bobOutputBlinderIndex,
		},
		{
			Asset:        usdt,
			Amount:       50000000,
			Script:       bobP2wpkh.WitnessScript,
			BlindingKey:  bobBlindingPublicKey.SerializeCompressed(),
			BlinderIndex: bobOutputBlinderIndex,
		},
	}

	err = updater.AddOutputs(bobOutputArgs)
	require.NoError(t, err)

	bobPrevTxHex, err := fetchTx(bobUtxos[0]["txid"].(string))
	require.NoError(t, err)

	bobPrevTx, _ := transaction.NewTxFromHex(bobPrevTxHex)
	bobAssetCommitment := h2b(bobUtxos[0]["assetcommitment"].(string))
	bobValueCommitment := h2b(bobUtxos[0]["valuecommitment"].(string))
	bobWitnessUtxo := &transaction.TxOutput{
		Asset:  bobAssetCommitment,
		Value:  bobValueCommitment,
		Script: bobP2wpkh.WitnessScript,
		Nonce:  bobPrevTx.Outputs[bobPrevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(1, bobWitnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(1, bobPrevTx.Outputs[bobPrevoutIndex].RangeProof)
	require.NoError(t, err)

	// Bob can now blind all outputs with his and alice's blinding private keys.
	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{
			aliceBlindingPrivateKey.Serialize(), bobBlindingPrivateKey.Serialize(),
		},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil)
	require.NoError(t, err)

	// Bob blinds the pset as last blinder.
	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	// Now that blinding is complete, both parties can sign the pset...
	prvKeys := []*btcec.PrivateKey{alicePrivkey, bobPrivkey}
	scripts := [][]byte{aliceP2wpkh.Script, bobP2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	// ...and broadcast the confidential swap tx to the network.
	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedTaprootKeyTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()

	taprootPay, err := payment.FromTaprootScriptTreeHash(pubkey, nil, &network.Regtest, blindingPublicKey)
	require.NoError(t, err)

	address, err := taprootPay.ConfidentialTaprootAddress()
	require.NoError(t, err)

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 60000000,
			Script: h2b("76a914f5b9864394bb5bc62691750cb32c9cbe522f0c3f88ac"),
		},
		{
			Asset:        lbtc,
			Amount:       39999500,
			Script:       taprootPay.Script,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: taprootPay.Script,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, []uint32{1})
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 500,
		},
	})
	require.NoError(t, err)

	tweakedPrivKey := taproot.TweakTaprootPrivKey(privkey, []byte{})

	genesisBlockhash, _ := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")
	unsignedTx, err := ptx.UnsignedTx()
	require.NoError(t, err)

	utxo := prevTx.Outputs[prevoutIndex]
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

	sig, err := schnorr.Sign(tweakedPrivKey, sighash[:])
	require.NoError(t, err)

	signer, err := psetv2.NewSigner(ptx)
	require.NoError(t, err)

	err = signer.SignTaprootInputKeySig(0, sig.Serialize())
	require.NoError(t, err)

	err = psetv2.Finalize(ptx, 0)
	require.NoError(t, err)

	_, err = extractAndBroadcast(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedTaprootTapscriptTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()

	checksigSchnorrScript, err := txscript.NewScriptBuilder().AddData(schnorr.SerializePubKey(pubkey)).AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)

	tree := taproot.AssembleTaprootScriptTree(taproot.NewBaseTapElementsLeaf(checksigSchnorrScript))
	leafProof := tree.LeafMerkleProofs[0] // we'll spend the coin using the first leaf

	taprootPay, err := payment.FromTaprootScriptTree(pubkey, tree, &network.Regtest, blindingPublicKey)
	require.NoError(t, err)

	address, err := taprootPay.ConfidentialTaprootAddress()
	require.NoError(t, err)

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 60000000,
			Script: h2b("76a914f5b9864394bb5bc62691750cb32c9cbe522f0c3f88ac"),
		},
		{
			Asset:        lbtc,
			Amount:       39999500,
			Script:       taprootPay.Script,
			BlindingKey:  blindingPublicKey.SerializeCompressed(),
			BlinderIndex: 0,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, nil)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:  assetCommitment,
		Value:  valueCommitment,
		Script: taprootPay.Script,
		Nonce:  prevTx.Outputs[prevoutIndex].Nonce,
	}
	err = updater.AddInWitnessUtxo(0, witnessUtxo)
	require.NoError(t, err)
	err = updater.AddInUtxoRangeProof(0, prevTx.Outputs[prevoutIndex].RangeProof)
	require.NoError(t, err)
	tapLeafScript := psetv2.NewTapLeafScript(leafProof, pubkey)
	err = updater.AddInTapLeafScript(0, tapLeafScript)
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, []uint32{1})
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  lbtc,
			Amount: 500,
		},
	})
	require.NoError(t, err)

	genesisBlockhash, _ := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")
	unsignedTx, err := ptx.UnsignedTx()
	require.NoError(t, err)

	utxo := prevTx.Outputs[prevoutIndex]
	leafHash := tapLeafScript.TapHash()

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

	sig, err := schnorr.Sign(privkey, sighash[:])
	require.NoError(t, err)

	tapScriptSig := psetv2.TapScriptSig{
		PartialSig: psetv2.PartialSig{
			PubKey:    schnorr.SerializePubKey(pubkey),
			Signature: sig.Serialize(),
		},
		LeafHash: leafHash[:],
	}

	signer, err := psetv2.NewSigner(ptx)
	require.NoError(t, err)

	err = signer.SignTaprootInputTapscriptSig(0, tapScriptSig)
	require.NoError(t, err)

	err = psetv2.Finalize(ptx, 0)
	require.NoError(t, err)

	_, err = extractAndBroadcast(ptx)
	require.NoError(t, err)
}
