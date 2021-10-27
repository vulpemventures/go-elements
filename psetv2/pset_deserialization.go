package psetv2

import (
	"bytes"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

func deserialize(buf *bytes.Buffer) (*Pset, error) {
	d := bufferutil.NewDeserializer(buf)

	magic, err := d.ReadSlice(uint(len(psetMagic)))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(magic, psetMagic) {
		return nil, ErrInvalidMagicBytes
	}

	global, err := deserializeGlobal(buf)
	if err != nil {
		return nil, err
	}

	inputs := make([]Input, 0)
	for i := 0; i < int(*global.txInfo.inputCount); i++ {
		input, err := deserializeInput(buf)
		if err != nil {
			return nil, err
		}

		inputs = append(inputs, *input)
	}

	outputs := make([]Output, 0)
	for i := 0; i < int(*global.txInfo.outputCount); i++ {
		output, err := deserializeOutput(buf)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, *output)
	}

	return &Pset{
		Global:  global,
		Inputs:  inputs,
		Outputs: outputs,
	}, nil
}
