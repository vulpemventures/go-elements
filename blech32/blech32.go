package blech32

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type EncodingType int64

const (
	BLECH32  EncodingType = 0x01
	BLECH32M EncodingType = 0x455972a3350f7a1
)

func EncodingTypeFromSegwitVersion(version byte) (EncodingType, error) {
	switch version {
	case 0x00:
		return BLECH32, nil
	case 0x01:
		return BLECH32M, nil
	default:
		return 0, fmt.Errorf("invalid witness version: %v", version)
	}
}

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

//new generators, 7 bytes compared to bech32
var gen = []int64{0x7d52fba40bd886, 0x5e8dbf1a03950c, 0x1c3a3c74072a18, 0x385d72fa0e5139, 0x7093e5a608865b}

// Decode decodes a blech32 encoded string, returning the human-readable
// part and the data part excluding the checksum.
func DecodeGeneric(blech string) (string, []byte, []byte, error) {
	// The maximum allowed length for a blech32 string is 1000. It must also
	// be at least 8 characters, since it needs a non-empty HRP, a
	// separator, and a 12 character checksum.
	if len(blech) < 8 || len(blech) > 1000 { //90 -> 1000 compared to bech32
		return "", nil, nil, fmt.Errorf("invalid blech32 string length %d",
			len(blech))
	}
	// Only	ASCII characters between 33 and 126 are allowed.
	for i := 0; i < len(blech); i++ {
		if blech[i] < 33 || blech[i] > 126 {
			return "", nil, nil, fmt.Errorf("invalid character in "+
				"string: '%c'", blech[i])
		}
	}

	// The characters must be either all lowercase or all uppercase.
	lower := strings.ToLower(blech)
	upper := strings.ToUpper(blech)
	if blech != lower && blech != upper {
		return "", nil, nil, fmt.Errorf("string not all lowercase or all " +
			"uppercase")
	}

	// We'll work with the lowercase string from now on.
	blech = lower

	// The string is invalid if the last '1' is non-existent, it is the
	// first character of the string (no human-readable part) or one of the
	// last 12 characters of the string (since checksum cannot contain '1'),
	// or if the string is more than 1000 characters in total.
	one := strings.LastIndexByte(blech, '1')
	if one < 1 || one+13 > len(blech) { //7 -> 13 compared to bech32
		return "", nil, nil, fmt.Errorf("invalid index of 1")
	}

	// The human-readable part is everything before the last '1'.
	hrp := blech[:one]
	data := blech[one+1:]

	// Each character corresponds to the byte with value of the index in
	// 'charset'.
	decoded, err := toBytes(data)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed converting data to bytes: "+
			"%v", err)
	}

	// We exclude the last 12 bytes, which is the checksum.
	return hrp, decoded[:len(decoded)-12], decoded[len(decoded)-12:], nil //6 - 12 compared to bech32
}

// Decode is like DecodeGeneric but also checks the checksum according to segwit version.
func Decode(addr string) (string, []byte, error) {
	hrp, data, checksum, err := DecodeGeneric(addr)
	if err != nil {
		return "", nil, err
	}

	encoding, err := EncodingTypeFromSegwitVersion(data[0])
	if err != nil {
		return hrp, data, err
	}

	if !verifyChecksum(hrp, append(data, checksum...), encoding) {
		expected, err := toChars(createChecksum(hrp, data, encoding))
		if err == nil {
			return hrp, data, fmt.Errorf("expected checksum %v, got %v", expected, hex.EncodeToString(checksum))
		} else {
			return hrp, data, fmt.Errorf("invalid checksum")
		}
	}

	return hrp, data, err
}

// Encode encodes a byte slice into a blech32 string with the
// human-readable part hrb. Note that the bytes must each encode 5 bits
// (base32).
func Encode(hrp string, data []byte, encoding EncodingType) (string, error) {
	// Calculate the checksum of the data and append it at the end.
	checksum := createChecksum(hrp, data, encoding)
	combined := append(data, checksum...)

	// The resulting blech32 string is the concatenation of the hrp, the
	// separator 1, data and checksum. Everything after the separator is
	// represented using the specified charset.
	dataChars, err := toChars(combined)
	if err != nil {
		return "", fmt.Errorf("unable to convert data bytes to chars: "+
			"%v", err)
	}
	return hrp + "1" + dataChars, nil
}

// toBytes converts each character in the string 'chars' to the value of the
// index of the correspoding character in 'charset'.
func toBytes(chars string) ([]byte, error) {
	decoded := make([]byte, 0, len(chars))
	for i := 0; i < len(chars); i++ {
		index := strings.IndexByte(charset, chars[i])
		if index < 0 {
			return nil, fmt.Errorf("invalid character not part of "+
				"charset: %v", chars[i])
		}
		decoded = append(decoded, byte(index))
	}
	return decoded, nil
}

// toChars converts the byte slice 'data' to a string where each byte in 'data'
// encodes the index of a character in 'charset'.
func toChars(data []byte) (string, error) {
	result := make([]byte, 0, len(data))
	for _, b := range data {
		if int(b) >= len(charset) {
			return "", fmt.Errorf("invalid data byte: %v", b)
		}
		result = append(result, charset[b])
	}
	return string(result), nil
}

// ConvertBits converts a byte slice where each byte is encoding fromBits bits,
// to a byte slice where each byte is encoding toBits bits.
func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	if fromBits < 1 || fromBits > 8 || toBits < 1 || toBits > 8 {
		return nil, fmt.Errorf("only bit groups between 1 and 8 allowed")
	}

	// The final bytes, each byte encoding toBits bits.
	var regrouped []byte

	// Keep track of the next byte we create and how many bits we have
	// added to it out of the toBits goal.
	nextByte := byte(0)
	filledBits := uint8(0)

	for _, b := range data {

		// Discard unused bits.
		b = b << (8 - fromBits)

		// How many bits remaining to extract from the input data.
		remFromBits := fromBits
		for remFromBits > 0 {
			// How many bits remaining to be added to the next byte.
			remToBits := toBits - filledBits

			// The number of bytes to next extract is the minimum of
			// remFromBits and remToBits.
			toExtract := remFromBits
			if remToBits < toExtract {
				toExtract = remToBits
			}

			// Add the next bits to nextByte, shifting the already
			// added bits to the left.
			nextByte = (nextByte << toExtract) | (b >> (8 - toExtract))

			// Discard the bits we just extracted and get ready for
			// next iteration.
			b = b << toExtract
			remFromBits -= toExtract
			filledBits += toExtract

			// If the nextByte is completely filled, we add it to
			// our regrouped bytes and start on the next byte.
			if filledBits == toBits {
				regrouped = append(regrouped, nextByte)
				filledBits = 0
				nextByte = 0
			}
		}
	}

	// We pad any unfinished group if specified.
	if pad && filledBits > 0 {
		nextByte = nextByte << (toBits - filledBits)
		regrouped = append(regrouped, nextByte)
		filledBits = 0
		nextByte = 0
	}

	// Any incomplete group must be <= 4 bits, and all zeroes.
	if filledBits > 0 && (filledBits > 4 || nextByte != 0) {
		return nil, fmt.Errorf("invalid incomplete group")
	}

	return regrouped, nil
}

// For more details on the checksum calculation, please refer to BIP 173.
func createChecksum(hrp string, data []byte, encoding EncodingType) []byte {
	// Convert the bytes to list of integers, as this is needed for the
	// checksum calculation.
	integers := make([]int, len(data))
	for i, b := range data {
		integers[i] = int(b)
	}
	values := append(blech32HrpExpand(hrp), integers...)
	values = append(values, []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...) //6->12 compared to bech32
	polymod := blech32Polymod(values) ^ int64(encoding)
	var res []byte
	for i := 0; i < 12; i++ { //6 -> 12 compared to bech32
		res = append(res, byte((polymod>>uint(5*(11-i)))&31)) //5 -> 11 compared to bech32
	}
	return res
}

// For more details on the polymod calculation, please refer to BIP 173.
func blech32Polymod(values []int) int64 {
	chk := int64(1)
	for _, v := range values {
		b := chk >> 55                                           //25->55 compared to bech32
		chk = (chk&int64(0x7fffffffffffff))<<int64(5) ^ int64(v) //0x1ffffff->0x7fffffffffffff compared to bech32
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// For more details on HRP expansion, please refer to BIP 173.
func blech32HrpExpand(hrp string) []int {
	v := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		v = append(v, int(hrp[i]>>5))
	}
	v = append(v, 0)
	for i := 0; i < len(hrp); i++ {
		v = append(v, int(hrp[i]&31))
	}
	return v
}

// For more details on the checksum verification, please refer to BIP 173.
func verifyChecksum(hrp string, data []byte, encodingType EncodingType) bool {
	integers := make([]int, len(data))
	for i, b := range data {
		integers[i] = int(b)
	}
	concat := append(blech32HrpExpand(hrp), integers...)
	return blech32Polymod(concat) == int64(encodingType)
}
