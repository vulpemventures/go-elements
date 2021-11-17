package psetv2

import (
	"errors"
)

var (
	ErrPsetAlreadyConstructed = errors.New("pset already constructed")
)

type Constructor struct {
	pset                *Pset
	inputArgs           []InputArg
	outputArgs          []OutputArg
	lockForModification bool
}

func NewConstructor(
	pset *Pset,
	inputArgs []InputArg,
	outputArgs []OutputArg,
	lockForModification bool,
) *Constructor {
	return &Constructor{
		inputArgs:           inputArgs,
		outputArgs:          outputArgs,
		lockForModification: lockForModification,
		pset:                pset,
	}
}

type TimeLock struct {
	RequiredTimeLock       *uint32
	RequiredHeightTimeLock *uint32
}

func (c *Constructor) Construct() (*Pset, error) {
	for _, v := range c.inputArgs {
		if err := c.pset.addInput(v); err != nil {
			return nil, err
		}
	}

	for _, v := range c.outputArgs {
		if err := c.pset.addOutput(v); err != nil {
			return nil, err
		}
	}

	if c.lockForModification {
		c.pset.LockForModification()
	}

	return c.pset, nil
}
