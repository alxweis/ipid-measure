package payload_tcp

import (
	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/seqnum"
	"github.com/alxweis/ipid-measure/ipid/tcp"
	"github.com/google/gopacket"
)

func Layer(seqNum uint16) []gopacket.SerializableLayer {
	if measurement.TcpEstablishConnection {
		// Request index for a connection computed from seqNum
		connectionIndex := seqnum.GetConnectionIndex(seqNum)

		// The First request for each connection is SYN for handshake
		if connectionIndex == 0 {
			return []gopacket.SerializableLayer{tcp.Layer(seqNum, sets.New(types.TCPFlagSYN))}
		}

		// The rest is a fragmented GET request
		tcpLayer := tcp.Layer(seqNum, sets.New(types.TCPFlagPSH, types.TCPFlagACK))
		payloadLayer := gopacket.Payload([]byte{tcp.Payload(connectionIndex - 1)})
		return []gopacket.SerializableLayer{tcpLayer, payloadLayer}
	}

	return []gopacket.SerializableLayer{tcp.Layer(seqNum, nil)}
}
