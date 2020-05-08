package utils

import (
	"bytes"
	"fmt"
)

// BufferWriter implements methods that help to serialize an Elements transaction.
type BufferWriter struct {
	buffer *bytes.Buffer
}

// NewBufferWriter returns an instance of BufferWriter.
func NewBufferWriter(buf *bytes.Buffer) (*BufferWriter, error) {
	buffer := bytes.NewBuffer([]byte{})
	if buf != nil {
		_, err := buffer.Write(buf.Bytes())
		if err != nil {
			return nil, err
		}
	}
	return &BufferWriter{buffer}, nil
}

// Bytes returns writer's buffer
func (bw *BufferWriter) Bytes() []byte {
	return bw.buffer.Bytes()
}

// WriteUint8 writes the given uint8 value to writer's buffer.
func (bw *BufferWriter) WriteUint8(val uint8) error {
	return BinarySerializer.PutUint8(bw.buffer, val)
}

// WriteUint16 writes the given uint8 value to writer's buffer.
func (bw *BufferWriter) WriteUint16(val uint16) error {
	return BinarySerializer.PutUint16(bw.buffer, littleEndian, val)
}

// WriteUint32 writes the given uint32 value to writer's buffer.
func (bw *BufferWriter) WriteUint32(val uint32) error {
	return BinarySerializer.PutUint32(bw.buffer, littleEndian, val)
}

// WriteUint64 writes the given uint64 value to writer's buffer.
func (bw *BufferWriter) WriteUint64(val uint64) error {
	return BinarySerializer.PutUint64(bw.buffer, littleEndian, val)
}

// WriteVarInt serializes the given value to writer's buffer
// using a variable number of bytes depending on its value.
func (bw *BufferWriter) WriteVarInt(val uint64) error {
	return writeVarInt(bw.buffer, val)
}

// WriteSlice appends the given byte array to the writer's buffer
func (bw *BufferWriter) WriteSlice(val []byte) error {
	_, err := bw.buffer.Write(val)
	return err
}

// WriteVarSlice appends the length of the given byte array as var int
// and the byte array itself to the writer's buffer
func (bw *BufferWriter) WriteVarSlice(val []byte) error {
	err := bw.WriteVarInt(uint64(len(val)))
	if err != nil {
		return err
	}
	return bw.WriteSlice(val)
}

// WriteVector appends an array of array bytes to the writer's buffer
func (bw *BufferWriter) WriteVector(v [][]byte) error {
	err := bw.WriteVarInt(uint64(len(v)))
	if err != nil {
		return err
	}
	for _, val := range v {
		err := bw.WriteVarSlice(val)
		if err != nil {
			return err
		}
	}
	return nil
}

// BufferReader implements methods that help to deserialize an Elements transaction.
type BufferReader struct {
	buffer *bytes.Buffer
}

// NewBufferReader returns an instance of BufferReader.
func NewBufferReader(buffer *bytes.Buffer) *BufferReader {
	return &BufferReader{buffer}
}

// ReadUint8 reads a uint8 value from reader's buffer.
func (br *BufferReader) ReadUint8() (uint8, error) {
	return BinarySerializer.Uint8(br.buffer)
}

// ReadUint16 reads a uint16 value from reader's buffer.
func (br *BufferReader) ReadUint16() (uint16, error) {
	return BinarySerializer.Uint16(br.buffer, littleEndian)
}

// ReadUint32 reads a uint32 value from reader's buffer.
func (br *BufferReader) ReadUint32() (uint32, error) {
	return BinarySerializer.Uint32(br.buffer, littleEndian)
}

// ReadUint64 reads a uint64 value from reader's buffer.
func (br *BufferReader) ReadUint64() (uint64, error) {
	return BinarySerializer.Uint64(br.buffer, littleEndian)
}

// ReadVarInt reads a variable length integer from reader's buffer and returns it as a uint64.
func (br *BufferReader) ReadVarInt() (uint64, error) {
	return readVarInt(br.buffer)
}

// ReadSlice reads the next n bytes from the reader's buffer
func (br *BufferReader) ReadSlice(n uint) ([]byte, error) {
	decoded := make([]byte, n)
	_, err := br.buffer.Read(decoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// ReadVarSlice first reads the length n of the bytes, then reads the next n bytes
func (br *BufferReader) ReadVarSlice() ([]byte, error) {
	n, err := br.ReadVarInt()
	if err != nil {
		return nil, err
	}
	return br.ReadSlice(uint(n))
}

// ReadVector reads the length n of the array of bytes, then reads the next n array bytes
func (br *BufferReader) ReadVector() ([][]byte, error) {
	n, err := br.ReadVarInt()
	if err != nil {
		return nil, err
	}
	v := [][]byte{}
	for i := uint(0); i < uint(n); i++ {
		val, err := br.ReadVarSlice()
		if err != nil {
			return nil, err
		}
		v = append(v, val)
	}
	return v, nil
}

// ReadElementsValue reads the first byte to determine if the value is
// confidential or unconfidential, then reads the right number of bytes accordingly.
func (br *BufferReader) ReadElementsValue() ([]byte, error) {
	version, err := br.ReadUint8()
	if err != nil {
		return nil, err
	}

	buf := []byte{version}
	nextBytes := []byte{}
	if version == 1 {
		nextBytes, err = br.ReadSlice(8)
		if err != nil {
			return nil, err
		}
	}
	if version == 8 || version == 9 {
		nextBytes, err = br.ReadSlice(32)
		if err != nil {
			return nil, err
		}
	}
	if len(nextBytes) == 0 {
		return nil, fmt.Errorf("Invalid prefix %d", version)
	}
	buf = append(buf, nextBytes...)
	return buf, nil
}

// ReadElementsAsset reads an Elements output asset form the reader's buffer
func (br *BufferReader) ReadElementsAsset() ([]byte, error) {
	version, err := br.ReadUint8()
	if err != nil {
		return nil, err
	}

	if version == 1 || version == 10 || version == 11 {
		b, err := br.ReadSlice(32)
		if err != nil {
			return nil, err
		}
		buf := []byte{version}
		buf = append(buf, b...)
		return buf, nil
	}

	return nil, fmt.Errorf("Invalid prefix %d", version)
}

// ReadElementsNonce reads a maybe non-zero Elements output nonce form the reader's buffer
func (br *BufferReader) ReadElementsNonce() ([]byte, error) {
	version, err := br.ReadUint8()
	if err != nil {
		return nil, err
	}

	buf := []byte{version}
	if version >= 1 && version <= 3 {
		b, err := br.ReadSlice(32)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
		return buf, nil
	}

	return buf, nil
}
