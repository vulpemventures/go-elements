// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (c) 2019-2020 The VulpemVentures developers

// A modification of the BIP-174 standard for Partial Signed Elements Transaction.
// (https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
package pset

// This package is designed in order to apply the possible fewer changes to the reference
// spec so that it can be used for Elements unblinded and blinded transactions.
// Essentially this version of partial transaction uses an underlying Elements unsigned
// transaction instead of a Bitcoin one, and the partial input WitnessUtxo field represents
// an Elements output rather than a Bitcoin one.
//
// NOTE: The Elements implementation of PSET is under development at the moment (take a look here)
// and this package will likely change in the future to adapt to this standard.
type PSET_PACKAGE int

// The creator is an exported factory function named simply New with the following signature:
//   func New(inputs []*transaction.TxInput, outputs []*transaction.TxOutput, version int32, nLockTime uint32) (*Pset, error) {}
// The role of this function is to simply create an unsigned partial transaction with the given inputs, outputs, version and locktime.
// The unblinded asset and amounts of the outputs are encoded into the "unsigned tx" field of the partial transaction.
func ROLE_1_Creator() *PSET_PACKAGE { return nil }

// The updater, as the name suggests, has the responsibility of updating the fields of any partial input or output.
// It consists of a collection of methods that, basically, has the purpose of adding any new field to an existing partial
// input (included issuance or reissuance placed in the unsigned tx) or output.
// It also allows to add new inputs or outputs to the underlying unsigned transaction.
// The updater can be instantiated by calling the NewUpdater factory function passing a partial transasction object.
func ROLE_2_Updater() *PSET_PACKAGE { return nil }

// At the moment the blinder role is designed to blind ALL the outputs of the partial transaction but
// this will change soon, letting one to blind only the set of outputs he wants.
// Also, this version of the blinder requires that all the private keys necessary
// to unblind all the confidential inputs used must be provided.
// Given this, the pset package is not useful in case multiple parties want to
// create a transaction by joining their inputs/outputs since they would need to
// reveal their blinding private keys and share them with the one encharged of assuming the blinder role.
// The pset package will change in the future to support the use case mentioned before, but this is not yet planned in the development.
func ROLE_3_Blinder() *PSET_PACKAGE { return nil }

// The signer is in charge of checking that when adding a signature to an input of the pset,
// this is valid and that also the pset is correctly structured. Given that, this role is implemented
// as a function Sign of the *Updater type. This function accepts an input index, a signature, a public key,
// and one between a redeem or witness script and checks that the signature is valid against the given script and pubkey,
// along with setting the partial input's signature script to the one provided.
func ROLE_4_Signer() *PSET_PACKAGE { return nil }

// The finalizer takes a partial transaction and combines every input's PartialSignature into the final input's
// SignatureScript. After finalizing, the partial transaction is complete, and it's ready to be extracted from the
// Pset wrapper and broadcasted to the network. This role is accomplished by a Finalize function that accepts a *Pset
//instance and an input index, and performs the operations described above, returning an error if any occurs during the process.
//It previously checks that the provided partial transaction is valid in the sense that it's ready to be finalized; otherwise,
// an error is returned. A handy FinalizeAll that runs the above method for every input of the provided *Pset is also exported.
func ROLE_5_Finalizer() *PSET_PACKAGE { return nil }

// The extractor is a simple Extract function expecting a finalized partial transaction that returns the final signed transaction
// by adding the signatures of the partial inputs to the underlying unsigned transaction.
func ROLE_6_Extractor() *PSET_PACKAGE { return nil }

/*
This is a simple exemplification on how to perform a basic P2PKH transaction using the PSET package

First, we will need a Private Key and derive a Public key from it. We'll follow by generating a P2PKH address.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			t.Fatal(err)
		}
	pubkey := privkey.PubKey()
	p2pkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2pkh.PubKeyHash()
Secondly, we need to fund the address with some UTXOs we can use as inputs.
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
	txInputHash = bufferutil.ReverseBytes(txInputHash)
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	lbtc, _ := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	)
	lbtc = append([]byte{0x01}, bufferutil.ReverseBytes(lbtc)...)

	receiverValue, _ := confidential.SatoshiToElementsValue(60000000)
	receiverScript := p2pkh.Script
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue[:], receiverScript)

	changeValue, _ := confidential.SatoshiToElementsValue(39999500)
	changeScript := p2pkh.Script
	changeOutput := transaction.NewTxOutput(lbtc, changeValue[:], changeScript)

	feeValue, _ := confidential.SatoshiToElementsValue(500)
	feeScript := []byte{}
	feeOutput := transaction.NewTxOutput(lbtc, feeValue[:], feeScript)

	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
This is where the Creator Role takes part.

We will create a new PSET:
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
And then the Updater Role begins its part:
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}
We'll need to add the sighash type and utxo to the partial input.
	updater.AddInSighashType(txscript.SigHashAll, 0)
	if err != nil {
		t.Fatal(err)
	}
	txH, err := fetchTx(utxos[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := transaction.NewTxFromHex(string(txH))
	if err != nil {
		t.Fatal(err)
	}
	updater.AddInNonWitnessUtxo(tx, 0)
After let's get a signature for the transaction.

We'll get the double sha256 hash of the serialization
of the transaction in order to then produce a signature from it and append the SigHash.
	nonwitHash, err := updater.Data.UnsignedTx.HashForSignature(0, p2pkh.Script, txscript.SigHashAll)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := privkey.Sign(nonwitHash[:])
	if err != nil {
		t.Fatal(err)
	}

	sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))

Update the PSET adding the input signature script and the pubkey.

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
	txHex, err := finalTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}
	txid, err := broadcast(txHex)
	if err != nil {
		t.Fatal(err)
	}
*/
func TX_P2PKH() *PSET_PACKAGE { return nil }

/*
This is a exemplification on how to perform a P2WPKH transaction with Blinded Outputs using the PSET package

First, we will need a Private Key and derive a Public key from it. We'll follow by generating a P2WPKH address.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()
Secondly, we need to fund the address with some UTXOs we can use as inputs.
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
	txInputHash = bufferutil.ReverseBytes(txInputHash)
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	lbtc, _ := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	)
	lbtc = append([]byte{0x01}, bufferutil.ReverseBytes(lbtc)...)
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
	txHex, err := finalTx.ToHex()
	if err != nil {
		t.Fatal(err)
	}
	_, err = broadcast(txHex)
	if err != nil {
		t.Fatal(err)
	}
*/
func TX_P2WPKHBLINDED() *PSET_PACKAGE { return nil }
