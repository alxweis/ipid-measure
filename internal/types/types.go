package types

import "github.com/alxweis/ipid-measure/internal/sets"

type TCPFlag = string

const (
	TCPFlagFIN TCPFlag = "F"
	TCPFlagSYN TCPFlag = "S"
	TCPFlagRST TCPFlag = "R"
	TCPFlagPSH TCPFlag = "P"
	TCPFlagACK TCPFlag = "A"
	TCPFlagURG TCPFlag = "U"
	TCPFlagECE TCPFlag = "E"
	TCPFlagCWR TCPFlag = "C"
	TCPFlagNS  TCPFlag = "N"
)

type DNSFlag = string

const (
	DNSFlagQR DNSFlag = "QR"
	DNSFlagAA DNSFlag = "AA"
	DNSFlagTC DNSFlag = "TC"
	DNSFlagRD DNSFlag = "RD"
	DNSFlagRA DNSFlag = "RA"
)

type TCPFlagSet = sets.Set[TCPFlag]
type DNSFlagSet = sets.Set[DNSFlag]

type ValidationStatus string

const (
	ValidationStatusFail   ValidationStatus = "fail"
	ValidationStatusPass   ValidationStatus = "pass"
	ValidationStatusIgnore ValidationStatus = "ignore"
)

type MeasurementMode string

const (
	MeasurementModeFixedInterval MeasurementMode = "fixed-interval"
	MeasurementModeRTBased       MeasurementMode = "rt-based"
)

type Payload string

// Payloads are composed of BPF-compatible protocol tokens joined by '-'
const (
	PayloadICMP   Payload = "icmp"
	PayloadTCP    Payload = "tcp"
	PayloadUDPDNS Payload = "udp-dns"
)
