package pset

import (
	"encoding/base64"
)

// Unknown is a struct encapsulating a key-value pair for which the key type is unknown
type Unknown struct {
	Key   []byte
	Value []byte
}

// Pset define partially signed Elements transaction
type Pset struct {
	UnsignedTx []byte
	Inputs     []interface{}
	Outputs    []interface{}
	Unknowns   []Unknown // Data of unknown type at global scope
}

// FromUnsignedTx instantiate Pset from unsigned raw transaction
// @param rawTransaction <[]byte> unsigned bitcoin transaction
// @return (*Pset, error) Pset instance and error
func (p *Pset) FromUnsignedTx(unsignedTx []byte) error {
	return nil
}

// FromBytes instantiate Pset from serialized pset
// @param pset Bytes <[]byte> unsigned bitcoin transaction
// @return (*Pset, error) Pset instance and error
func (p *Pset) FromBytes(psetBytes []byte) error {
	return nil
}

// ToBytes serialize current pset
// @return ([]byte, error) pset bytes or an error
func (p *Pset) ToBytes() ([]byte, error) {
	return []byte{}, nil
}

// Encode returns base64 encoding of the current serialization of PSET
// @return (string, error) base64 pset encoded or an error
func (p *Pset) Encode() (string, error) {
	raw, err := p.ToBytes()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

// Decode returns Pset of base64 encoded string
// @param pset <string> base64 pset encoded
// @return (*Pset, error) Pset instance and error
func Decode(pset string) (*Pset, error) {
	psetBytes := []byte(pset)

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(psetBytes)))
	_, err := base64.StdEncoding.Decode(decoded, psetBytes)
	if err != nil {
		return nil, err
	}

	psetBytes = decoded

	p := &Pset{}
	err = p.FromBytes(psetBytes)
	if err != nil {
		return nil, err
	}

	return p, nil
}
