package payload_tcp

import (
	"github.com/google/gopacket"
	"github.com/netd-tud/ipid-measure/internal/sets"
	"github.com/netd-tud/ipid-measure/internal/types"
	"github.com/netd-tud/ipid-measure/ipid/measurement"
	"github.com/netd-tud/ipid-measure/ipid/seqnum"
	"github.com/netd-tud/ipid-measure/ipid/tcp"
)

func Layer(seqNum uint16) []gopacket.SerializableLayer {
	if measurement.TcpEstablishConnection {
		// request index for a connection computed from seqNum
		connectionIndex := seqnum.GetConnectionIndex(seqNum)

		// the first request for each connection is SYN for handshake
		if connectionIndex == 0 {
			return []gopacket.SerializableLayer{tcp.Layer(seqNum, sets.New(types.TCPFlagSYN))}
		}

		// rest is fragmented GET request
		tcpLayer := tcp.Layer(seqNum, sets.New(types.TCPFlagPSH, types.TCPFlagACK))
		payloadLayer := gopacket.Payload([]byte{tcp.Payload(connectionIndex - 1)})
		return []gopacket.SerializableLayer{tcpLayer, payloadLayer}
	}

	return []gopacket.SerializableLayer{tcp.Layer(seqNum, nil)}
}
