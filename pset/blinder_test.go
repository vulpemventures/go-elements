package pset

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/transaction"
)

func ExampleNewBlinder() {
	inputs := []*transaction.TxInput{}
	outputs := []*transaction.TxOutput{}
	p, err := New(inputs, outputs, 2, 0)

	pk, err := btcec.NewPrivateKey(btcec.S256())
	blindingpubkey := pk.PubKey().SerializeCompressed()
	blindingPubKeys := make([][]byte, 0)
	blindingPubKeys = append(blindingPubKeys, blindingpubkey)
	blindingPrivKeys := [][]byte{}

	blinder, err := NewBlinder(
		p,
		blindingPrivKeys,
		blindingPubKeys,
		nil,
		nil,
	)
}
