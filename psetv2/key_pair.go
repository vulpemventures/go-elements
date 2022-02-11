package psetv2

import (
	"bytes"
	"fmt"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

var (
	ErrKeyInvalidSize               = fmt.Errorf("invalid key size")
	ErrProprietaryInvalidKey        = fmt.Errorf("invalid ProprietaryData key")
	ErrProprietaryInvalidIdentifier = fmt.Errorf("invalid ProprietaryData identifier")
)

// keyPair format:
//<keypair> := <key> <value>
//<key> := <keylen> <keytype> <keydata>
//<value> := <valuelen> <valuedata>
type KeyPair struct {
	Key   Key
	Value []byte
}

type Key struct {
	KeyType uint8
	KeyData []byte
}

func (k *KeyPair) serialize(s *bufferutil.Serializer) error {
	if err := k.Key.serialize(s); err != nil {
		return err
	}

	return s.WriteVarSlice(k.Value)
}

func (k *KeyPair) deserialize(buf *bytes.Buffer) error {
	d := bufferutil.NewDeserializer(buf)

	if err := k.Key.deserialize(d); err != nil {
		return err
	}

	value, err := d.ReadVarSlice()
	if err != nil {
		return err
	}

	k.Value = value

	return nil
}

func (k *Key) serialize(s *bufferutil.Serializer) error {
	key := append([]byte{k.KeyType}, k.KeyData...)
	return s.WriteVarSlice(key)
}

func (k *Key) deserialize(d *bufferutil.Deserializer) error {
	key, err := d.ReadVarSlice()
	if err != nil {
		return err
	}

	if len(key) == 0 {
		return ErrNoMoreKeyPairs
	}

	if len(key) > maxPsbtKeyLength {
		return ErrKeyInvalidSize
	}

	k.KeyType = key[0]
	k.KeyData = key[1:]

	return nil
}

type ProprietaryData struct {
	Identifier []byte
	Subtype    uint8
	KeyData    []byte
	Value      []byte
}

func (p *ProprietaryData) fromKeyPair(keyPair KeyPair) error {
	d := bufferutil.NewDeserializer(bytes.NewBuffer(keyPair.Key.KeyData))

	if keyPair.Key.KeyType != 0xFC {
		return ErrProprietaryInvalidKey
	}

	identifierByteSize, err := d.ReadVarInt()
	if err != nil {
		return err
	}

	if identifierByteSize == 0 {
		return ErrProprietaryInvalidIdentifier
	}

	identifier, err := d.ReadSlice(uint(identifierByteSize))
	if err != nil {
		return err
	}

	subType, err := d.ReadUint8()
	if err != nil {
		return err
	}

	keyData := d.ReadToEnd()

	value := keyPair.Value

	p.Identifier = identifier
	p.Subtype = subType
	p.KeyData = keyData
	p.Value = value

	return nil
}

func proprietaryKey(subType uint8, keyData []byte) []byte {
	result := make([]byte, 0)
	result = append(result, byte(len(magicPrefix)-1))
	result = append(result, magicPrefix[:len(magicPrefix)-1]...)
	result = append(result, subType)
	if keyData != nil {
		result = append(result, keyData...)
	}

	return result
}
