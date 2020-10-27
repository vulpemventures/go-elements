package pset

func ExampleNewPsetInput_witnessUtxo() {
	pInput := p.Inputs[inIndex]
	newInput := NewPsetInput(nil, pInput.WitnessUtxo)
}

func ExampleNewPsetInput_nonWitnessUtxo() {
	pInput := p.Inputs[inIndex]
	newInput := NewPsetInput(pInput.NonWitnessUtxo, nil)
}
