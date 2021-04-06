package block

import (
	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

func (b *Block) SerializeBlock() ([]byte, error) {
	s, err := bufferutil.NewSerializer(nil)
	if err != nil {
		return nil, err
	}

	err = b.Header.SerializeHeader(s)
	if err != nil {
		return nil, err
	}

	err = b.Transactions.SerializeTransactions(s)
	if err != nil {
		return nil, err
	}

	return s.Bytes(), nil
}

func (t *Transactions) SerializeTransactions(
	s *bufferutil.Serializer,
) error {
	err := s.WriteVarInt(uint64(len(t.Transactions)))
	if err != nil {
		return err
	}
	for _, v := range t.Transactions {
		txBytes, err := v.Serialize()
		if err != nil {
			return err
		}

		err = s.WriteSlice(txBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *Header) SerializeHeader(
	s *bufferutil.Serializer,
) error {
	if h.ExtData.IsDyna {
		err := s.WriteUint32(dynaVersion)
		if err != nil {
			return err
		}
	} else {
		err := s.WriteUint32(proofVersion)
		if err != nil {
			return err
		}
	}

	err := s.WriteSlice(h.PrevBlockHash)
	if err != nil {
		return err
	}

	err = s.WriteSlice(h.MerkleRoot)
	if err != nil {
		return err
	}

	err = s.WriteUint32(h.Timestamp)
	if err != nil {
		return err
	}

	err = s.WriteUint32(h.Height)
	if err != nil {
		return err
	}

	err = h.ExtData.serialize(s)
	if err != nil {
		return err
	}

	return nil
}

func (e *ExtData) serialize(
	s *bufferutil.Serializer,
) error {
	if e.IsDyna {
		err := e.DynamicFederation.serialize(s)
		if err != nil {
			return err
		}
	} else {
		err := e.Proof.serialize(s)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Proof) serialize(
	s *bufferutil.Serializer,
) error {
	err := s.WriteVarInt(uint64(len(p.Challenge)))
	if err != nil {
		return err
	}

	err = s.WriteSlice(p.Challenge)
	if err != nil {
		return err
	}

	err = s.WriteVarInt(uint64(len(p.Solution)))
	if err != nil {
		return err
	}

	err = s.WriteSlice(p.Solution)
	if err != nil {
		return err
	}

	return nil
}

func (d *DynamicFederation) serialize(
	s *bufferutil.Serializer,
) error {
	if d.Current == nil {
		err := s.WriteUint8(null)
		if err != nil {
			return err
		}
	} else {
		err := d.Current.serialize(s)
		if err != nil {
			return err
		}
	}

	if d.Proposed == nil {
		err := s.WriteUint8(null)
		if err != nil {
			return err
		}
	} else {
		err := d.Proposed.serialize(s)
		if err != nil {
			return err
		}
	}

	err := s.WriteVarInt(uint64(len(d.SignBlockWitness)))
	if err != nil {
		return err
	}

	for i := 0; i < len(d.SignBlockWitness); i++ {
		err = s.WriteVarInt(uint64(len(d.SignBlockWitness[i])))
		if err != nil {
			return err
		}

		err = s.WriteSlice(d.SignBlockWitness[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *DynamicFederationParams) serialize(
	s *bufferutil.Serializer,
) error {
	if d.CompactParams == nil && d.FullParams == nil {
		err := s.WriteUint8(null)
		if err != nil {
			return err
		}
	}

	if d.CompactParams != nil {
		err := s.WriteUint8(compact)
		if err != nil {
			return err
		}

		err = d.CompactParams.serialize(s)
		if err != nil {
			return err
		}
	}

	if d.FullParams != nil {
		err := s.WriteUint8(full)
		if err != nil {
			return err
		}

		err = d.FullParams.serialize(s)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CompactParams) serialize(
	s *bufferutil.Serializer,
) error {
	err := s.WriteVarInt(uint64(len(c.SignBlockScript)))
	if err != nil {
		return err
	}

	err = s.WriteSlice(c.SignBlockScript)
	if err != nil {
		return err
	}

	err = s.WriteUint32(c.SignBlockWitnessLimit)
	if err != nil {
		return err
	}

	err = s.WriteSlice(c.ElidedRoot)
	if err != nil {
		return err
	}

	return nil
}

func (f *FullParams) serialize(
	s *bufferutil.Serializer,
) error {
	err := s.WriteVarInt(uint64(len(f.SignBlockScript)))
	if err != nil {
		return err
	}

	err = s.WriteSlice(f.SignBlockScript)
	if err != nil {
		return err
	}

	err = s.WriteUint32(f.SignBlockWitnessLimit)
	if err != nil {
		return err
	}

	err = s.WriteVarInt(uint64(len(f.FedpegProgram)))
	if err != nil {
		return err
	}

	err = s.WriteSlice(f.FedpegProgram)
	if err != nil {
		return err
	}

	err = s.WriteVarInt(uint64(len(f.FedpegScript)))
	if err != nil {
		return err
	}

	err = s.WriteSlice(f.FedpegScript)
	if err != nil {
		return err
	}

	err = s.WriteVarInt(uint64(len(f.ExtensionSpace)))
	if err != nil {
		return err
	}

	for i := 0; i < len(f.ExtensionSpace); i++ {
		err = s.WriteVarInt(uint64(len(f.ExtensionSpace[i])))
		if err != nil {
			return err
		}

		err = s.WriteSlice(f.ExtensionSpace[i])
		if err != nil {
			return err
		}
	}

	return nil
}
