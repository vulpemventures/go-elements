package psetv2

import (
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

func (p *Pset) serialize() ([]byte, error) {
	if p == nil {
		return nil, errors.New("")
	}

	s, err := bufferutil.NewSerializer(nil)
	if err != nil {
		return nil, err
	}

	if err := s.WriteSlice(psetMagic); err != nil {
		return nil, err
	}

	if err := p.Global.serialize(s); err != nil {
		return nil, err
	}

	for _, v := range p.Inputs {
		if err := v.serialize(s); err != nil {
			return nil, err
		}
	}

	for _, v := range p.Outputs {
		if err := v.serialize(s); err != nil {
			return nil, err
		}
	}

	return s.Bytes(), nil
}
