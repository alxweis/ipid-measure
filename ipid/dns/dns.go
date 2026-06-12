package dns

import (
	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
)

const Sld = "example.com"

func Layer(seqNum uint16) gopacket.SerializableLayer {
	return &layers.DNS{
		ID:      seqNum,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      false,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(strconv.FormatUint(uint64(seqNum), 10) + "." + Sld),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
}

func GetFlags(dns *layers.DNS) types.DNSFlagSet {
	flags := sets.New[types.DNSFlag]()

	add := func(enabled bool, flag types.DNSFlag) {
		if enabled {
			flags.Add(flag)
		}
	}

	add(dns.QR, types.DNSFlagQR)
	add(dns.AA, types.DNSFlagAA)
	add(dns.TC, types.DNSFlagTC)
	add(dns.RD, types.DNSFlagRD)
	add(dns.RA, types.DNSFlagRA)

	return flags
}
