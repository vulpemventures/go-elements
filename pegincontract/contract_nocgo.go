//go:build !cgo

package pegincontract

import (
	"errors"
)

var errNoCGO = errors.New("pegin contract requires CGO")

// Calculate calculates the pegin contract.
// This is a no-op implementation when CGO is disabled.
func Calculate(
	federationScript []byte,
	scriptPubKey []byte,
) ([]byte, error) {
	return nil, errNoCGO
}

// IsLiquidV1 checks if the script is a Liquid V1 script.
// This is a no-op implementation when CGO is disabled.
func IsLiquidV1(script []byte) (bool, error) {
	return false, errNoCGO
}
