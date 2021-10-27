package psetv2

import (
	"bytes"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

// keyPair format:
//<keypair> := <key> <value>
//<key> := <keylen> <keytype> <keydata>
//<value> := <valuelen> <valuedata>
type keyPair struct {
	key   key
	value []byte
}

type key struct {
	keyType uint8
	keyData []byte
}

func serializeKeyPair(kp keyPair, s *bufferutil.Serializer) error {
	if err := s.WriteVarInt(uint64(len(kp.key.keyData) + 1)); err != nil {
		return err
	}

	if err := s.WriteUint8(kp.key.keyType); err != nil {
		return err
	}

	if err := s.WriteSlice(kp.key.keyData); err != nil {
		return err
	}

	if err := s.WriteVarInt(uint64(len(kp.value))); err != nil {
		return err
	}

	if err := s.WriteSlice(kp.value); err != nil {
		return err
	}

	return nil
}

func (k *keyPair) deserialize(buf *bytes.Buffer) error {
	if err := k.key.deserialize(buf); err != nil {
		return err
	}

	d := bufferutil.NewDeserializer(buf)
	valueSize, err := d.ReadVarInt()
	if err != nil {
		return err
	}

	valueData, err := d.ReadSlice(uint(valueSize))
	if err != nil {
		return err
	}

	k.value = valueData

	return nil
}

func (k *key) deserialize(buf *bytes.Buffer) error {
	d := bufferutil.NewDeserializer(buf)

	keyByteSize, err := d.ReadVarInt()
	if err != nil {
		return err
	}

	if keyByteSize == 0 {
		return ErrNoMoreKeyPairs
	}

	if keyByteSize > maxPsbtKeyLength {
		return ErrInvalidKeySize
	}

	key, err := d.ReadSlice(uint(keyByteSize))
	if err != nil {
		return err
	}

	keyType := key[0]
	k.keyType = keyType
	k.keyData = nil
	if len(key) > 1 {
		k.keyData = key[1:]
	}

	return nil
}

type proprietaryData struct {
	identifier []byte
	subtype    uint8
	keyData    []byte
	value      []byte
}

func (p *proprietaryData) proprietaryDataFromKeyPair(keyPair keyPair) error {
	d := bufferutil.NewDeserializer(bytes.NewBuffer(keyPair.key.keyData))

	if keyPair.key.keyType != 0xFC {
		return ErrInvalidProprietaryKey
	}

	identifierByteSize, err := d.ReadVarInt()
	if err != nil {
		return err
	}

	if identifierByteSize == 0 {
		return ErrInvalidProprietaryIdentifier
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

	value := keyPair.value

	p.identifier = identifier
	p.subtype = subType
	p.keyData = keyData
	p.value = value

	return nil
}

func proprietaryKey(subType uint8, keyData []byte) []byte {
	result := make([]byte, 0)
	result = append(result, byte(len(psetMagic)-1))
	result = append(result, psetMagic[:len(psetMagic)-1]...)
	result = append(result, subType)
	if keyData != nil {
		result = append(result, keyData...)
	}

	return result
}

func deserializeUnknownKeyPairs(buf *bytes.Buffer) ([]keyPair, error) {
	unknowns := make([]keyPair, 0)
	for {
		kp := &keyPair{}
		if err := kp.deserialize(buf); err != nil {
			if err == ErrNoMoreKeyPairs {
				break
			}
			return nil, err
		}
		unknowns = append(unknowns, *kp)
	}

	return unknowns, nil
}
