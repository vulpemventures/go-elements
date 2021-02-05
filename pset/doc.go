/*
Package pset is a modification of the BIP-174 standard for Partial Signed Elements Transaction. (https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)

This is an exemplification on how to perform a P2WPKH transaction using the PSET package
with the assistance of vulpemventures/nigiri for funding the address, retrieving the UTXOs and broadcasting.

    	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address. This function calls the API of vulpemventures/nigiri.
	_, err = faucet(address)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos. This function calls the API of vulpemventures/nigiri.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
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

	updater.AddInSighashType(txscript.SigHashAll, 0)
	if err != nil {
		t.Fatal(err)
	}
	witValue, _ := confidential.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue[:], p2wpkh.WitnessScript)
	updater.AddInWitnessUtxo(witnessUtxo, 0)

	// The signing of the input is done by retrieving the proper hash of the serialization of the transaction
	witHash := updater.Data.UnsignedTx.HashForWitnessV0(0, p2wpkh.Script, witValue[:], txscript.SigHashAll)
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

	valid, err := updater.Data.ValidateAllSignatures()
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal(errors.New("invalid signatures"))
	}

	// Finalize the partial transaction.
	p = updater.Data
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
	// This function calls the API of vulpemventures/nigiri.
	txid, err := broadcast(txHex)
	if err != nil {
		t.Fatal(err)
	}

	if len(txid) <= 0 {
		t.Fatal("Expected transaction to be broadcasted")
	}
*/
package pset
