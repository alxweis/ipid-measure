package seqnum

import "github.com/alxweis/ipid-measure/ipid/measurement"

func GetConnectionIndex(seqNum uint16) uint16 {
	return seqNum % measurement.Config.ConnectionCount
}

func GetRequestIndex(seqNum uint16) uint16 {
	return seqNum / measurement.Config.ConnectionCount
}

// TCPSequenceNumber returns a sequence number that advances independently for
// each TCP connection. The SYN consumes one sequence number and every following
// request carries one payload byte.
func TCPSequenceNumber(offset uint32, seqNum, connectionCount uint16) uint32 {
	connectionIndex := uint32(seqNum % connectionCount)
	requestIndex := uint32(seqNum / connectionCount)
	return offset + connectionIndex + requestIndex
}

// FromTCPAcknowledgment maps a TCP acknowledgment and destination port back to
// the flattened request index used by Probe.Samples.
func FromTCPAcknowledgment(
	acknowledgment uint32,
	offset uint32,
	destinationPort uint16,
	basePort uint16,
	connectionCount uint16,
	requestsPerConnection uint16,
) (uint16, bool) {
	if connectionCount == 0 || destinationPort < basePort {
		return 0, false
	}

	connectionIndex := destinationPort - basePort
	if connectionIndex >= connectionCount {
		return 0, false
	}

	minimumAcknowledgment := offset + uint32(connectionIndex) + 1
	if acknowledgment < minimumAcknowledgment {
		return 0, false
	}

	requestIndex := acknowledgment - minimumAcknowledgment
	if requestIndex >= uint32(requestsPerConnection) {
		return 0, false
	}

	seqNum := requestIndex*uint32(connectionCount) + uint32(connectionIndex)
	return uint16(seqNum), true
}
