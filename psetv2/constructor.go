package psetv2

import (
	"errors"

	"github.com/vulpemventures/go-elements/transaction"
)

var (
	ErrPsetAlreadyConstructed = errors.New("pset already constructed")
)

type Constructor struct {
	pset *Pset
}

func NewConstructor(pset *Pset) *Constructor {
	return &Constructor{
		pset: pset,
	}
}

type TimeLock struct {
	RequiredTimeLock       *uint32
	RequiredHeightTimeLock *uint32
}

func (c *Constructor) Construct(
	inputs map[TimeLock]transaction.TxInput,
	outputs []transaction.TxOutput,
	lockForModification bool,
) (*Pset, error) {
	for k, v := range inputs {
		if err := c.pset.AddInput(k, v); err != nil {
			return nil, err
		}
	}

	for _, v := range outputs {
		if err := c.pset.AddOutput(v); err != nil {
			return nil, err
		}
	}

	if lockForModification {
		c.pset.LockForModification()
	}

	return c.pset, nil
}
