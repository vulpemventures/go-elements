package psetv2

import (
	"fmt"
	"math"
	"math/bits"
)

const (
	bitsetSize = 8
)

type BitSet []byte

func NewBitSet() BitSet {
	return make(BitSet, bitsetSize)
}

func NewBitSetFromBuffer(buf byte) (BitSet, error) {
	return bitSetFromBuffer(uint8(buf)), nil
}

func (s BitSet) String() string {
	var str string
	for _, v := range s.reverse() {
		str += fmt.Sprintf("%d", v)
	}
	return str
}

func (s BitSet) Set(index int) {
	if index >= len(s) {
		return
	}
	s[index] = 1
}

func (s BitSet) Reset(index int) {
	if index >= len(s) {
		return
	}
	s[index] = 0
}

func (s BitSet) Test(index int) bool {
	if index >= len(s) {
		return false
	}
	return s[index] == 1
}

func (s BitSet) Clear() {
	s = NewBitSet()
}

func (s BitSet) Uint8() uint8 {
	var n uint8
	for i, v := range s {
		n += v * uint8(math.Pow(2, float64(i)))
	}
	return n
}

func (s BitSet) reverse() []byte {
	b := make(BitSet, 0, len(s))
	for _, v := range s {
		b = append([]byte{v}, b...)
	}
	return b
}

func bitSetFromBuffer(u uint8) BitSet {
	base := 2
	s := NewBitSet()
	i := 0
	shift := uint(bits.TrailingZeros(uint(base))) & 7
	b := uint8(base)
	m := uint(base) - 1
	for u >= b {
		s[i] = byte(uint(u) & m)
		u >>= shift
		i++
	}
	s[i] = byte(uint(u))
	return s
}
