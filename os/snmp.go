package os

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SNMPProbe sends a single SNMPv2c GET-Request for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
// to udp/161 and returns the responder's sysDescr string. One UDP packet out,
// one UDP packet back, with a short timeout: this is the cheapest possible
// OS-fingerprint probe and can be parallelised much more aggressively than
// the TCP-based scanners.
//
// We do not depend on a third-party SNMP library: the protocol surface we use
// here (single GET for one scalar OID) is small enough that a focused
// implementation is more reliable and quite a bit faster than a generic one.
type SNMPProbe struct {
	community []byte
	timeout   time.Duration
}

// NewSNMPProbe builds a probe with the given v2c community string and per-
// request timeout (no retries).
func NewSNMPProbe(community string, timeout time.Duration) *SNMPProbe {
	return &SNMPProbe{
		community: []byte(community),
		timeout:   timeout,
	}
}

// SNMPResult is the per-target outcome of a sysDescr query.
type SNMPResult struct {
	IP       string
	SysDescr string // empty if no response or no sysDescr value
	OK       bool   // true iff we got a valid SNMP response with a string varBind
}

// Run streams targets in from `in`, sends one SNMP GET-Request per target
// with `workers` goroutines, and emits results on `out`. The returned
// channel `out` is closed when `in` closes AND all workers have drained.
//
// On any error per target (DNS, network unreachable, timeout, malformed
// reply) the worker emits SNMPResult{IP: target, OK: false} so the merger
// has a record of the attempt -- this lets the merger know "snmp for this
// IP is done" even when there was no useful result.
//
// All ctx.Done() checks ensure a clean shutdown on SIGINT: workers exit
// promptly even while blocked on a slow consumer.
func (p *SNMPProbe) Run(ctx context.Context, in <-chan string, workers int) <-chan SNMPResult {
	out := make(chan SNMPResult, 1024)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Per-worker scratch buffer; reused across all probes.
			buf := make([]byte, 1500)
			for target := range in {
				select {
				case <-ctx.Done():
					return
				default:
				}
				descr, ok := p.probeOne(ctx, target, buf)
				select {
				case out <- SNMPResult{IP: target, SysDescr: descr, OK: ok}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// probeOne sends one GET-Request for sysDescr.0 and waits for the reply.
// On any error returns ("", false). On a successful reply with a string
// varBind value returns (value, true).
func (p *SNMPProbe) probeOne(ctx context.Context, target string, buf []byte) (string, bool) {
	deadline := time.Now().Add(p.timeout)
	if dctx, ok := ctx.Deadline(); ok && dctx.Before(deadline) {
		deadline = dctx
	}

	conn, err := net.DialTimeout("udp4", net.JoinHostPort(target, "161"), p.timeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	reqID := nextRequestID()
	pkt, err := buildSysDescrGet(p.community, reqID)
	if err != nil {
		return "", false
	}
	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}

	n, err := conn.Read(buf)
	if err != nil {
		return "", false
	}
	return parseSysDescrReply(buf[:n], reqID, p.community)
}

// requestIDCounter is a monotonic counter for SNMP request IDs.
var requestIDCounter atomic.Int32

func nextRequestID() int32 {
	v := requestIDCounter.Add(1)
	// Stay positive (SNMP request-id is INTEGER, but negative values can
	// confuse some buggy agents).
	if v <= 0 {
		v &= 0x7fffffff
	}
	return v
}

// ---------------------------------------------------------------------------
// Wire-format helpers.
//
// The SNMPv2c message structure (RFC 1905/3416 over RFC 3417 BER):
//
//   Message ::= SEQUENCE {
//       version       INTEGER,        -- 1 = v2c
//       community     OCTET STRING,
//       data          GetRequest-PDU  -- [0] IMPLICIT
//   }
//
//   GetRequest-PDU ::= [0] IMPLICIT SEQUENCE {
//       request-id    INTEGER,
//       error-status  INTEGER,        -- 0
//       error-index   INTEGER,        -- 0
//       variable-bindings SEQUENCE OF VarBind
//   }
//
//   VarBind ::= SEQUENCE {
//       name    OBJECT IDENTIFIER,
//       value   ANY                   -- NULL in requests
//   }
// ---------------------------------------------------------------------------

// sysDescrOID is 1.3.6.1.2.1.1.1.0 (SNMPv2-MIB::sysDescr.0).
var sysDescrOID = asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0}

// buildSysDescrGet assembles a v2c GET-Request for sysDescr.0.
func buildSysDescrGet(community []byte, reqID int32) ([]byte, error) {
	// varBind: { OID=sysDescr.0, value=NULL }
	varBind := struct {
		Name  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{
		Name: sysDescrOID,
		Value: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagNull,
			IsCompound: false,
			Bytes:      nil,
		},
	}
	varBindList := []any{varBind}

	pdu := struct {
		RequestID   int32
		ErrorStatus int
		ErrorIndex  int
		VarBindList []any
	}{
		RequestID:   reqID,
		ErrorStatus: 0,
		ErrorIndex:  0,
		VarBindList: varBindList,
	}

	// Encode the inner GetRequest-PDU first so we know its bytes, then wrap
	// it with the GetRequest IMPLICIT tag (context-specific 0).
	pduBytes, err := asn1.Marshal(pdu)
	if err != nil {
		return nil, fmt.Errorf("encode pdu: %w", err)
	}
	// Strip the outer SEQUENCE header asn1.Marshal added, then re-wrap with
	// the GetRequest tag.
	if len(pduBytes) < 2 || pduBytes[0] != 0x30 {
		return nil, errors.New("encode pdu: unexpected encoding")
	}
	// The implicit tag for GetRequest-PDU is [0] context-specific, constructed.
	// 0xa0 = class=context(2)|compound(1)|tag(0) = 10 100000.
	getRequest := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      pduBytes[lenOfHeader(pduBytes):], // payload of the SEQUENCE
	}

	msg := struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}{
		Version:   1, // SNMPv2c
		Community: community,
		PDU:       getRequest,
	}
	return asn1.Marshal(msg)
}

// lenOfHeader returns the length in bytes of the BER tag+length prefix at the
// start of `b`. b[0] is the tag; b[1] is the length-byte (short or long form).
func lenOfHeader(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	if b[1]&0x80 == 0 {
		return 2 // short form: tag + 1 length byte
	}
	return 2 + int(b[1]&0x7f) // long form: tag + 1 + N length bytes
}

// parseSysDescrReply attempts to find a non-empty string varBind value in a
// SNMPv2c response. Returns (value, true) on success, ("", false) on any
// parse failure or mismatched request-id/community.
//
// Tolerant of agents that reorder varBinds or wrap the value in OCTET STRING
// with various sub-types -- we extract the OCTET STRING value regardless of
// what variable name the agent chose (since we only asked for one OID, any
// returned value belongs to it).
func parseSysDescrReply(reply []byte, expectedReqID int32, expectedCommunity []byte) (string, bool) {
	var msg struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}
	if _, err := asn1.Unmarshal(reply, &msg); err != nil {
		return "", false
	}
	if !bytesEqual(msg.Community, expectedCommunity) {
		return "", false
	}

	// PDU is implicitly tagged context-specific 2 for GetResponse-PDU. We
	// don't enforce the tag value (some agents use 2 for v2c, others reuse
	// the same wrapper); we just decode the inner SEQUENCE content.
	pduBody := msg.PDU.Bytes

	// Inside the PDU: RequestID INTEGER, error-status INT, error-index INT,
	// then SEQUENCE OF VarBind.
	var requestID int32
	rest, err := asn1.Unmarshal(pduBody, &requestID)
	if err != nil {
		return "", false
	}
	if requestID != expectedReqID {
		return "", false
	}
	var errorStatus int
	rest, err = asn1.Unmarshal(rest, &errorStatus)
	if err != nil {
		return "", false
	}
	if errorStatus != 0 {
		return "", false
	}
	var errorIndex int
	rest, err = asn1.Unmarshal(rest, &errorIndex)
	if err != nil {
		return "", false
	}
	// Now `rest` starts with SEQUENCE OF VarBind. Unmarshal once and dig in.
	var vbList asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &vbList); err != nil {
		return "", false
	}
	vbBytes := vbList.Bytes
	for len(vbBytes) > 0 {
		var vb asn1.RawValue
		next, err := asn1.Unmarshal(vbBytes, &vb)
		if err != nil {
			return "", false
		}
		// Inside one VarBind SEQUENCE: OBJECT IDENTIFIER (the name) then the
		// value. We skip the OID and read whatever follows. Any non-empty
		// printable OCTET STRING counts as the sysDescr.
		var name asn1.ObjectIdentifier
		valBytes, err := asn1.Unmarshal(vb.Bytes, &name)
		if err == nil && len(valBytes) > 0 {
			var v asn1.RawValue
			if _, err := asn1.Unmarshal(valBytes, &v); err == nil {
				if v.Tag == asn1.TagOctetString && len(v.Bytes) > 0 {
					return string(v.Bytes), true
				}
			}
		}
		vbBytes = next
	}
	return "", false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
