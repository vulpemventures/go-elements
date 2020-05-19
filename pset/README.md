# PSET

A [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) compatible partial signed elements transaction encoding go package.

## Creator

The creator is an exported factory function named just `New` that accepts a list of tx inputs, a list of tx outputs, a tx version and locktime, and returns a new instance of `*Pset` containing an unsigned transaction.

## Updater

The updater, as the name suggests, has the responsibility of updating the fields of any partial input or output. Thus, basically, for any field of the `PInput` and `POutput` type, the `Updater` type exposes a function `AddIn<PInputfieldName>` and `AddOut<POutputFieldName>`.  
To create a new updater, a factory function `NewUpdater` accepting a `*Pset` instance and returning a `*Updater` one is exposed.

## Signer

The signer is in charge of checking that when adding a signature to an input of the pset, this is valid and that also the pset is correctly structured.  
Given that, this role is implemented as a function `Sign` of the `*Updater` type.  
This function accepts an input index, a signature, a public key, and one between a redeem or witness script and checks that the signature is valid against the given script and pubkey, along with setting the partial input's signature script to the one provided.

## Finalizer

The finalizer takes a partial transaction and combines every input's `PartialSignature` into the final input's `SignatureScript`. After finalizing, the partial transaction is complete, and it's ready to be extracted from the `Pset` wrapper and broadcasted to the network.  
This role is accomplished by a `Finalize` function that accepts a `*Pset` instance and an input index, and performs the operations described above, returning an error if any occurs during the process. It previously checks that the provided partial transaction is valid in the sense that it's ready to be finalized; otherwise, an error is returned.  
A handy `FinalizeAll` that runs the above method for every input of the provided \*Pset is also exported.

## Extractor

The extractor is a simple `Extract` function that accepting a `*Pset` instance that checks that the provided partial transaction is complete (it returns an error otherwise), then make a copy of the pset's `UnsignedTx` and for every partial input adds the final input `SignatureScript` and `PublicKey` to the input witnesses. After this, the `*Transaction` instance is returned.
