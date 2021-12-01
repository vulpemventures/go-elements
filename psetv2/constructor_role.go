package psetv2

import (
	"errors"
)

var (
	ErrPsetAlreadyConstructed = errors.New("pset already constructed")
)

type ConstructorRole struct {
	pset                *Pset
	inputArgs           []InputArg
	outputArgs          []OutputArg
	lockForModification bool
}

func NewConstructorRole(
	pset *Pset,
	inputArgs []InputArg,
	outputArgs []OutputArg,
	lockForModification bool,
) (*ConstructorRole, error) {
	return &ConstructorRole{
		inputArgs:           inputArgs,
		outputArgs:          outputArgs,
		lockForModification: lockForModification,
		pset:                pset,
	}, nil
}

type TimeLock struct {
	RequiredTimeLock       *uint32
	RequiredHeightTimeLock *uint32
}

func (c *ConstructorRole) Construct() error {
	for _, v := range c.inputArgs {
		if err := c.pset.addInput(v); err != nil {
			return err
		}
	}

	for _, v := range c.outputArgs {
		if err := c.pset.addOutput(v); err != nil {
			return err
		}
	}

	if c.lockForModification {
		c.pset.LockForModification()
	}

	return nil
}
