package block

import (
	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

func (b *Block) SerializeBlock() ([]byte, error) {
	s, err := bufferutil.NewSerializer(nil)
	if err != nil {
		return nil, err
	}

	err = b.Header.Serialize(s)
	if err != nil {
		return nil, err
	}

	err = b.TransactionsData.Serialize(s)
	if err != nil {
		return nil, err
	}

	return s.Bytes(), nil
}

func (t *Transactions) Serialize(
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

func (h *Header) Serialize(
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

	if err := s.WriteSlice(h.PrevBlockHash); err != nil {
		return err
	}

	if err := s.WriteSlice(h.MerkleRoot); err != nil {
		return err
	}

	if err := s.WriteUint32(h.Timestamp); err != nil {
		return err
	}

	if err := s.WriteUint32(h.Height); err != nil {
		return err
	}

	if err := h.ExtData.serialize(s); err != nil {
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
	if err := s.WriteVarInt(uint64(len(p.Challenge))); err != nil {
		return err
	}

	if err := s.WriteSlice(p.Challenge); err != nil {
		return err
	}

	if err := s.WriteVarInt(uint64(len(p.Solution))); err != nil {
		return err
	}

	if err := s.WriteSlice(p.Solution); err != nil {
		return err
	}

	return nil
}

func (d *DynamicFederation) serialize(
	s *bufferutil.Serializer,
) error {
	if d.Current == nil {
		if err := s.WriteUint8(null); err != nil {
			return err
		}
	} else {
		if err := d.Current.serialize(s); err != nil {
			return err
		}
	}

	if d.Proposed == nil {
		if err := s.WriteUint8(null); err != nil {
			return err
		}
	} else {
		if err := d.Proposed.serialize(s); err != nil {
			return err
		}
	}

	if err := s.WriteVarInt(uint64(len(d.SignBlockWitness))); err != nil {
		return err
	}

	for i := 0; i < len(d.SignBlockWitness); i++ {
		if err := s.WriteVarInt(uint64(len(d.SignBlockWitness[i]))); err != nil {
			return err
		}

		if err := s.WriteSlice(d.SignBlockWitness[i]); err != nil {
			return err
		}
	}

	return nil
}

func (d *DynamicFederationParams) serialize(
	s *bufferutil.Serializer,
) error {
	if d.CompactParams == nil && d.FullParams == nil {
		if err := s.WriteUint8(null); err != nil {
			return err
		}
	}

	if d.CompactParams != nil {
		if err := s.WriteUint8(compact); err != nil {
			return err
		}

		if err := d.CompactParams.serialize(s); err != nil {
			return err
		}
	}

	if d.FullParams != nil {
		if err := s.WriteUint8(full); err != nil {
			return err
		}

		if err := d.FullParams.serialize(s); err != nil {
			return err
		}
	}

	return nil
}

func (c *CompactParams) serialize(
	s *bufferutil.Serializer,
) error {
	if err := s.WriteVarInt(uint64(len(c.SignBlockScript))); err != nil {
		return err
	}

	if err := s.WriteSlice(c.SignBlockScript); err != nil {
		return err
	}

	if err := s.WriteUint32(c.SignBlockWitnessLimit); err != nil {
		return err
	}

	if err := s.WriteSlice(c.ElidedRoot); err != nil {
		return err
	}

	return nil
}

func (f *FullParams) serialize(
	s *bufferutil.Serializer,
) error {
	if err := s.WriteVarInt(uint64(len(f.SignBlockScript))); err != nil {
		return err
	}

	if err := s.WriteSlice(f.SignBlockScript); err != nil {
		return err
	}

	if err := s.WriteUint32(f.SignBlockWitnessLimit); err != nil {
		return err
	}

	if err := s.WriteVarInt(uint64(len(f.FedpegProgram))); err != nil {
		return err
	}

	if err := s.WriteSlice(f.FedpegProgram); err != nil {
		return err
	}

	if err := s.WriteVarInt(uint64(len(f.FedpegScript))); err != nil {
		return err
	}

	if err := s.WriteSlice(f.FedpegScript); err != nil {
		return err
	}

	if err := s.WriteVarInt(uint64(len(f.ExtensionSpace))); err != nil {
		return err
	}

	for i := 0; i < len(f.ExtensionSpace); i++ {
		if err := s.WriteVarInt(uint64(len(f.ExtensionSpace[i]))); err != nil {
			return err
		}

		if err := s.WriteSlice(f.ExtensionSpace[i]); err != nil {
			return err
		}
	}

	return nil
}
