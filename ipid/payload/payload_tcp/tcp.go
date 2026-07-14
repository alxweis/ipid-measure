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
		// Request index within one connection, computed from the flattened seqNum.
		requestIndex := seqnum.GetRequestIndex(seqNum)

		// The First request for each connection is SYN for handshake
		if requestIndex == 0 {
			return []gopacket.SerializableLayer{tcp.Layer(seqNum, sets.New(types.TCPFlagSYN))}
		}

		// The rest is a fragmented GET request
		tcpLayer := tcp.Layer(seqNum, sets.New(types.TCPFlagPSH, types.TCPFlagACK))
		payloadLayer := gopacket.Payload([]byte{tcp.Payload(requestIndex - 1)})
		return []gopacket.SerializableLayer{tcpLayer, payloadLayer}
	}

	return []gopacket.SerializableLayer{tcp.Layer(seqNum, nil)}
}
