// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (c) 2019-2020 The VulpemVentures developers

/*
This is a exemplification on how to perform a P2WPKH transaction with Blinded Outputs using the PSET package
with the assistance of vulpemventures/nigiri for funding the address, retrieving the UTXOs and broadcasting.

You can run this example with this command.
Check its behaviour on Nigiri's Esplora (http://localhost:5001/).
  $ go test ./pset -v -count 1 -run TestBroadcastBlindedTx

First, we will need a Private Key and derive a Public key from it. We'll follow by generating a P2WPKH address.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()
Secondly, we need to fund the address with some UTXOs we can use as inputs.
This functions require Nigiri Chopsticks for the API calls.
	_, err = faucet(address)
	if err != nil {
		t.Fatal(err)
	}
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}
We need inputs and outputs in order to create a new PSET.

The transaction will have 1 Input and 3 Outputs.
The input we just funded from the faucet and three outputs.

One for the ammount we want to send, one for the change and a last one for the fee.
	txInputHash, _ := hex.DecodeString(utxos[0]["txid"].(string))
	txInputHash = elementsutil.ReverseBytes(txInputHash)
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	lbtc, _ := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	)
	lbtc = append([]byte{0x01}, elementsutil.ReverseBytes(lbtc)...)
	receiverValue, _ := confidential.SatoshiToElementsValue(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue[:], receiverScript)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := confidential.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], changeScript)
This is where the Creator Role takes part.

We will create a new PSET with all the outputs that need to be blinded first.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
And then the Updater Role begins its part:
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}
We'll need to add the sighash type and witnessUtxo to the partial input.
	err = updater.AddInSighashType(txscript.SigHashAll, 0)
	if err != nil {
		t.Fatal(err)
	}
	witValue, _ := confidential.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue[:], p2wpkh.WitnessScript)
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	if err != nil {
		t.Fatal(err)
	}
Next, we'll Blind the Outputs. This is where the Blinder Role takes part.

This version of the blinder requires that all the private keys
necessary to unblind all the confidential inputs used must be provided.
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
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = blinder.Blind()
	if err != nil {
		t.Fatal(err)
	}
We'll add the unblinded outputs now, that's only the fee output in this case.
	feeScript := []byte{}
	feeValue, _ := confidential.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)
	updater.AddOutput(feeOutput)
After we need a signature for the transaction.

We'll get the double sha256 hash of the serialization
of the transaction in order to then produce a witness signature for the given inIndex input and append the SigHash.
	witHash := updater.Data.UnsignedTx.HashForWitnessV0(0, p2wpkh.Script, witValue[:], txscript.SigHashAll)
	sig, err := privkey.Sign(witHash[:])
	if err != nil {
		t.Fatal(err)
	}
	sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))
Now we Update the PSET adding the input signature script and the pubkey.

The Signer role handles this task as a function Sign of the *Updater type.
	_, err = updater.Sign(0, sigWithHashType, pubkey.SerializeCompressed(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := updater.Data.ValidateAllSignatures()
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal(errors.New("invalid signatures"))
	}
The Finalizer role handles this part of the PSET. We'll combine every input's
PartialSignature into the final input's SignatureScript.
	p = updater.Data
	err = FinalizeAll(p)
	if err != nil {
		t.Fatal(err)
	}
Now the partial transaction is complete, and it's ready to be
extracted from the Pset wrapper. This is implented in the Extractor Role.
	finalTx, err := Extract(p)
	if err != nil {
		t.Fatal(err)
	}
Finally, our transaction is ready to be serialized and broadcasted to the network.
The Broadcast function require Nigiri Chopsticks for the API call.
	txHex, err := finalTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}
	_, err = broadcast(txHex)
	if err != nil {
		t.Fatal(err)
	}
*/
package main
