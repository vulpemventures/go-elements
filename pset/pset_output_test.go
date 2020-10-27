package pset

func ExampleNewPsbtOutput_nil() {
	newOutput := NewPsbtOutput(nil, nil, nil)
}

func ExampleNewPsbtOutput_redeemScript() {
	newOutput := NewPsbtOutput(redeemScript, nil, nil)
}
