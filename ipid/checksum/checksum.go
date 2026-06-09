package checksum

// Compute Standard referring RFC1071
func Compute(data []byte) uint16 {
	var sum uint32

	// Add all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		word := uint32(data[i])<<8 + uint32(data[i+1])
		sum += word
	}

	// If odd number of Bytes, add the last byte
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}
