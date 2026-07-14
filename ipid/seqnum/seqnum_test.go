package seqnum

import "testing"

func TestEstablishedTCPSequenceRoundTrip(t *testing.T) {
	const (
		offset                = uint32(1_000_000)
		basePort              = uint16(40_000)
		connectionCount       = uint16(4)
		requestsPerConnection = uint16(4)
	)

	requestCount := connectionCount * requestsPerConnection
	for seqNum := uint16(0); seqNum < requestCount; seqNum++ {
		connectionIndex := seqNum % connectionCount
		tcpSequence := TCPSequenceNumber(offset, seqNum, connectionCount)
		acknowledgment := tcpSequence + 1

		got, ok := FromTCPAcknowledgment(
			acknowledgment,
			offset,
			basePort+connectionIndex,
			basePort,
			connectionCount,
			requestsPerConnection,
		)
		if !ok {
			t.Fatalf("seqNum %d was rejected", seqNum)
		}
		if got != seqNum {
			t.Fatalf("seqNum %d round-tripped as %d", seqNum, got)
		}
	}
}

func TestFromTCPAcknowledgmentRejectsInvalidValues(t *testing.T) {
	const (
		offset                = uint32(1_000_000)
		basePort              = uint16(40_000)
		connectionCount       = uint16(4)
		requestsPerConnection = uint16(4)
	)

	tests := []struct {
		name string
		ack  uint32
		port uint16
	}{
		{name: "port below range", ack: offset + 1, port: basePort - 1},
		{name: "port above range", ack: offset + 1, port: basePort + connectionCount},
		{name: "ack below connection sequence", ack: offset + 1, port: basePort + 1},
		{name: "request above range", ack: offset + uint32(requestsPerConnection) + 1, port: basePort},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := FromTCPAcknowledgment(
				test.ack,
				offset,
				test.port,
				basePort,
				connectionCount,
				requestsPerConnection,
			); ok {
				t.Fatal("invalid acknowledgment was accepted")
			}
		})
	}
}
