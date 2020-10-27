// This is a file header. It is separated from the package doc below with an
// empty line so it is ignored by Godoc. This area can be used for copyright
// notifications and/or internal descriptions of the file that you do not want
// to show.

// Package godoctricks is a tutorial that deals with tricks for making your
// godoc organized and neat. This is a compilation of tricks I've collected and
// couldn't find a comprehensive guide for.
package pset

// A modification of the BIP-174 standard for Partial Signed Elements Transaction
// (https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
//
// Changes from the standard reference:
//
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
func Creator() *PSET_PACKAGE

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
func P2WPKH_TX() *PSET_PACKAGE

// Methods are attached to their receiver type in the godoc, regardless of
// their physical location in the code.
func (Methods) Foo() {}

// Pointer receivers are also associated in the same way.
func (*Methods) Foo2() {}

// Functions that construct an instance of a type (or a pointer to it) are
// associated with the returned type.
func NewMethods() *Methods { return nil }
