package elementsutil

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

// SatoshiToElementsValue method converts Satoshi value to Elements value
func SatoshiToElementsValue(val uint64) ([]byte, error) {
	unconfPrefix := byte(1)
	b := bytes.NewBuffer([]byte{})
	if err := bufferutil.BinarySerializer.PutUint64(b, binary.LittleEndian, val); err != nil {
		return nil, err
	}
	res := append([]byte{unconfPrefix}, bufferutil.ReverseBytes(b.Bytes())...)
	return res, nil
}

// ElementsToSatoshiValue method converts Elements value to Satoshi value
func ElementsToSatoshiValue(val []byte) (uint64, error) {
	if len(val) != 9 {
		return 0, errors.New("invalid elements value lenght")
	}
	if val[0] != byte(1) {
		return 0, errors.New("invalid prefix")
	}
	reverseValueBuffer := bufferutil.ReverseBytes(val[1:])
	d := bufferutil.NewDeserializer(bytes.NewBuffer(reverseValueBuffer))
	return d.ReadUint64()
}
