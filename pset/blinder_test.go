package pset

func ExampleNewBlinder() {
	p, err := New(inputs, outputs, 2, 0)
	blindingPubKeys = append(blindingPubKeys, blindingpubkey2)
	blindingPrivKeys := [][]byte{pk.Serialize(), pk1.Serialize()}

	blinder, err := NewBlinder(
		p,
		blindingPrivKeys,
		blindingPubKeys,
		nil,
		nil,
	)
}
