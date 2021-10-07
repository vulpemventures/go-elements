package psetv2

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

const (
	separator        = 0x00
	maxPsbtKeyLength = 10000
)

var (
	psetMagic = []byte{0x70, 0x73, 0x65, 0x74, 0xFF} //'pset' string with magic separator 0xFF

	ErrNoMoreKeyPairs               = errors.New("no more key-pairs")
	ErrInvalidKeySize               = errors.New("invalid key size")
	ErrInvalidProprietaryKey        = errors.New("invalid proprietaryData key")
	ErrInvalidProprietaryIdentifier = errors.New("invalid proprietaryData identifier")
	ErrInvalidMagicBytes            = errors.New("invalid magic bytes")
)

// Pset - Partially signed Element's transaction
//Format:
//<pset> := <magic> <global-map> <input-map>* <output-map>*
//<magic> := 0x70 0x73 0x65 0x74 0xFF -> pset starts with magic bytes, after which goes global map
//followed by more input-map's and output-map's
//<global-map> := <keypair>* 0x00 -> there is one global-map, there can be many keypair's, global map ends with separator
//<input-map> := <keypair>* 0x00 -> there can be many input-map's, there can be many keypair's, input map ends with separator
//<output-map> := <keypair>* 0x00 -> there can be many output-map's, there can be many keypair's, output map ends with separator
//<keypair> := <key> <value>
//<key> := <keylen> <keytype> <keydata>
//<value> := <valuelen> <valuedata>
// Each map can contain proprietaryData data and unknowns keypair's
// Full spec: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
type Pset struct {
	Global  *Global
	Inputs  []Input
	Outputs []Output
}

func NewFromBuffer(buf *bytes.Buffer) (*Pset, error) {
	return deserialize(buf)
}

func NewFromHex(h string) (*Pset, error) {
	hexBytes, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(hexBytes)
	return NewFromBuffer(buf)
}

func deserialize(buf *bytes.Buffer) (*Pset, error) {
	d := bufferutil.NewDeserializer(buf)

	magic, err := d.ReadSlice(uint(len(psetMagic)))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(magic, psetMagic) {
		return nil, ErrInvalidMagicBytes
	}

	global, err := deserializeGlobal(buf)
	if err != nil {
		return nil, err
	}

	inputs := make([]Input, 0)
	for i := 0; i < int(global.txInfo.inputCount); i++ {
		input, err := deserializeInput(buf)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, *input)
	}

	outputs := make([]Output, 0)
	for i := 0; i < int(global.txInfo.inputCount); i++ {
		output, err := deserializeOutput(buf)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, *output)
	}

	return &Pset{
		Global:  global,
		Inputs:  inputs,
		Outputs: outputs,
	}, nil
}

// keyPair format:
//<keypair> := <key> <value>
//<key> := <keylen> <keytype> <keydata>
//<value> := <valuelen> <valuedata>
type keyPair struct {
	key   key
	value []byte
}

type key struct {
	keyType int
	keyData []byte
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

	keyType := int(key[0])
	k.keyType = keyType
	k.keyData = nil
	if len(key) > 1 {
		k.keyData = key[1:]
	}

	return nil
}

type proprietaryData struct {
	identifier []byte
	subtype    int
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
	p.subtype = int(subType)
	p.keyData = keyData
	p.value = value

	return nil
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
