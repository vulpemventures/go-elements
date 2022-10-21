package elementsutil

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

// ValueToBytes method converts Satoshi value to Elements value
func ValueToBytes(val uint64) ([]byte, error) {
	unconfPrefix := byte(1)
	b := bytes.NewBuffer([]byte{})
	if err := bufferutil.BinarySerializer.PutUint64(b, binary.LittleEndian, val); err != nil {
		return nil, err
	}
	res := append([]byte{unconfPrefix}, ReverseBytes(b.Bytes())...)
	return res, nil
}

// ElementsToSatoshiValue method converts Elements value to Satoshi value
func ValueFromBytes(val []byte) (uint64, error) {
	if len(val) != 9 {
		return 0, errors.New("invalid elements value lenght")
	}
	if val[0] != byte(1) {
		return 0, errors.New("invalid prefix")
	}
	reverseValueBuffer := ReverseBytes(val[1:])
	d := bufferutil.NewDeserializer(bytes.NewBuffer(reverseValueBuffer))
	return d.ReadUint64()
}

func AssetHashFromBytes(buffer []byte) string {
	// We remove the first byte from the buffer array that represents if confidential or unconfidential
	return hex.EncodeToString(ReverseBytes(buffer[1:]))
}

func AssetHashToBytes(str string) ([]byte, error) {
	buffer, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	buffer = ReverseBytes(buffer)
	buffer = append([]byte{0x01}, buffer...)
	return buffer, nil
}

func TxIDFromBytes(buffer []byte) string {
	return hex.EncodeToString(ReverseBytes(buffer))
}

func TxIDToBytes(str string) ([]byte, error) {
	buffer, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return ReverseBytes(buffer), nil
}

func CommitmentFromBytes(buffer []byte) string {
	return hex.EncodeToString(buffer)
}

func CommitmentToBytes(str string) ([]byte, error) {
	return hex.DecodeString(str)
}

// ReverseBytes returns a copy of the given byte slice with elems in reverse order.
func ReverseBytes(buf []byte) []byte {
	if len(buf) < 1 {
		return buf
	}
	tmp := make([]byte, len(buf))
	copy(tmp, buf)
	for i := len(tmp)/2 - 1; i >= 0; i-- {
		j := len(tmp) - 1 - i
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}
	return tmp
}

func ValidElementValue(val []byte) bool {
	return len(val) == 9 && val[0] == byte(1)
}
