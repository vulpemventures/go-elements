# PSET

A modification of the [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) standard for Partial Signed Elements Transaction.

## Changes from the standard reference

This package is designed in order to apply the possible fewer changes to the reference spec so that it can be used for Elements unblinded and blinded transactions.

Essentially this version of partial transaction uses an underlying Elements unsigned transaction instead of a Bitcoin one, and the partial input `WitnessUtxo` field represents an Elements output rather than a Bitcoin one. 

NOTE: The Elements implementation of PSET is under development at the moment (take a look [here]()) and this package will likely change in the future to adapt to this standard.

## Creator

The creator is an exported factory function named simply `New` with the following signature:

```
func New(inputs []*transaction.TxInput, outputs []*transaction.TxOutput, version int32, nLockTime uint32) (*Pset, error) {}
```

The role of this function is to simply create an unsigned partial transaction wiwht the given inputs, outputs, version and locktime.  
The unblinded asset and amounts of the outputs are encoded into the "unsigned tx" field of the partial transaction.

## Updater

The updater, as the name suggests, has the responsibility of updating the fields of any partial input or output. It consists of a collection of methods that, basically, has the purpose of adding any new field to an existing partial input (included issuance or reissuance placed in the unsigned tx) or output.  
It also allows to add new inputs or outputs to the underlying unsigned transaction.

The updater can be instantiated by calling the `NewUpdater` factory function passing a partial transasction object.

## Blinder

At the moment the blinder role is designed to blind ALL the outputs of the partial transaction, but this will change soon, letting one to blind only the set of outputs he wants.  
Also, this version of the blinder requires that all the private keys necessary to unblind all the confidential inputs used must be provided.  
Given this, the *pset* package is not useful in case multiple parties want to create a transaction by joining their inputs/outputs since they would need to reveal their blinding private keys and share them with the one encharged of assuming the blinder role.  
The *pset* package will change in the future to support the use case mentioned before, but this is not yet planned in the development.

## Signer

The signer is in charge of checking that when adding a signature to an input of the pset, this is valid and that also the pset is correctly structured.
Given that, this role is implemented as a function `Sign` of the `*Updater` type.
This function accepts an input index, a signature, a public key, and one between a redeem or witness script and checks that the signature is valid against the given script and pubkey, along with setting the partial input's signature script to the one provided.

## Finalizer

The finalizer takes a partial transaction and combines every input's `PartialSignature` into the final input's `SignatureScript`. After finalizing, the partial transaction is complete, and it's ready to be extracted from the `Pset` wrapper and broadcasted to the network.
This role is accomplished by a `Finalize` function that accepts a `*Pset` instance and an input index, and performs the operations described above, returning an error if any occurs during the process. It previously checks that the provided partial transaction is valid in the sense that it's ready to be finalized; otherwise, an error is returned.
A handy `FinalizeAll` that runs the above method for every input of the provided \*Pset is also exported.

## Extractor

The extractor is a simple `Extract` function expecting a finalized partial transaction that returns the final signed transaction by adding the signatures of the partial inputs to the underlying unsigned transaction.
