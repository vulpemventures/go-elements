package bufferutil

// ReverseBytes returns the given byte slice with elems in reverse order.
func ReverseBytes(buf []byte) []byte {
	if len(buf) < 1 {
		return buf
	}
	for i := len(buf)/2 - 1; i >= 0; i-- {
		j := len(buf) - 1 - i
		buf[i], buf[j] = buf[j], buf[i]
	}
	return buf
}
