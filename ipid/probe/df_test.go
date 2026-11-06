package probe

import (
	"bytes"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/parquet-go/parquet-go"
)

func TestDFBelongsToFirstAcceptedReply(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, df := range []bool{false, true} {
			name := "mass"
			if strict {
				name = "base"
			}
			if df {
				name += "/df1"
			} else {
				name += "/df0"
			}
			t.Run(name, func(t *testing.T) {
				p, key := baseFixture(t)
				p.strict = strict
				p.Samples[0].MarkSent(100)
				if !FulfillReply(key, sender.SenderA.IPBytes, 40000, 0, 2000, 42, types.SynAckFlagSet, 200, 0, df) {
					t.Fatal("valid reply rejected")
				}
				if FulfillReply(key, sender.SenderA.IPBytes, 40000, 0, 2000, 99, types.SynAckFlagSet, 201, 0, !df) {
					t.Fatal("duplicate accepted")
				}
				s := &p.Samples[0]
				if !s.IsReceived() || s.IpID != 42 || s.ReceiveTime != 200 || s.DontFragment != df {
					t.Fatal("duplicate changed accepted IPID, timestamp, or DF")
				}
			})
		}
	}
}

func TestRejectedReplyDoesNotStoreDF(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, reason := range []string{"late", "before-send", "flags", "unsent", "wrong-source"} {
			t.Run(fmtDFMode(strict)+"/"+reason, func(t *testing.T) {
				p, key := baseFixture(t)
				p.strict = strict
				p.Samples[0].MarkSent(100)
				received, flags, dst := int64(200), types.SynAckFlagSet, sender.SenderA.IPBytes
				switch reason {
				case "late":
					received = 101 + time.Second.Microseconds()
				case "before-send":
					received = 99
				case "flags":
					flags = types.AckFlagSet
				case "unsent":
					p.Samples[0] = Sample{}
				case "wrong-source":
					dst = [4]byte{203, 0, 113, 5}
				}
				if FulfillReply(key, dst, 40000, 0, 2000, 99, flags, received, 0, true) || p.Samples[0].IsReceived() || p.Samples[0].DontFragment {
					t.Fatal("rejected reply stored DF")
				}
			})
		}
	}
}

func fmtDFMode(strict bool) string {
	if strict {
		return "base"
	}
	return "mass"
}

func TestSamplePublishesMatchingDFWithConcurrentReplies(t *testing.T) {
	var sample Sample
	sample.MarkSent(100)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for id := uint16(1); id <= 32; id++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			if sample.TryFill(id, 200+int64(id), id%2 == 1) {
				accepted.Add(1)
			}
		}(id)
	}
	// IsReceived publishes the complete sample, including DF, atomically.
	for !sample.IsReceived() {
		time.Sleep(time.Microsecond)
	}
	if sample.DontFragment != (sample.IpID%2 == 1) || sample.ReceiveTime != 200+int64(sample.IpID) {
		t.Fatal("published fields came from different replies")
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("more than one reply filled the sample")
	}
}

func TestLegacyParquetDoesNotImplyDFZero(t *testing.T) {
	var buffer bytes.Buffer
	type legacyRecord struct {
		IPAddress                string `parquet:"IP_ADDR"`
		IPIDSequence             string `parquet:"IPID_SEQUENCE"`
		SendTimestampSequence    string `parquet:"SEND_TIMESTAMP_SEQUENCE"`
		ReceiveTimestampSequence string `parquet:"RECEIVE_TIMESTAMP_SEQUENCE"`
	}
	w := parquet.NewGenericWriter[legacyRecord](&buffer)
	if _, err := w.Write([]legacyRecord{{"192.0.2.1", "42", "100", "200"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := parquet.Read[records.IPIDRecord](bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil || len(rows) != 1 || rows[0].DFSequence != "" {
		t.Fatalf("legacy DF must remain unknown: rows=%+v err=%v", rows, err)
	}
}

func TestDFSequenceSavedForAllMeasurementLayouts(t *testing.T) {
	for _, variant := range []string{"rt-base", "fixed-base", "mass", "connection", "interprotocol-base", "interprotocol-mass"} {
		t.Run(variant, func(t *testing.T) {
			p, key := baseFixture(t)
			previousPaths, previousProtocols, previousSave := measurement.Paths, measurement.InterProtocols, SaveProbesChannel
			t.Cleanup(func() {
				measurement.Paths, measurement.InterProtocols, SaveProbesChannel = previousPaths, previousProtocols, previousSave
			})
			measurement.InterProtocols = nil
			measurement.Paths = &paths.IPIDMeasurement{}
			rt := variant == "rt-base"
			if rt {
				measurement.Config.MeasurementMode = types.MeasurementModeRTBased
			}
			interprotocol := strings.HasPrefix(variant, "interprotocol-")
			mass := variant == "mass" || variant == "interprotocol-mass"
			if mass {
				measurement.Config.RequestsPerConnection = 25
				measurement.RequestCount = 100
				p.strict = false
			}
			if interprotocol {
				measurement.InterProtocols = []types.Payload{types.PayloadICMP, types.PayloadTCP, types.PayloadUDPDNS}
				measurement.RequestCount *= 3
				p.TargetStrategy = "SINGLE"
			}
			p.Samples = make([]Sample, measurement.RequestCount)
			p.Target = net.IP(key[:])
			wantDF := make([]string, len(p.Samples))
			wantIPID := make([]string, len(p.Samples))
			// Reverse arrival order must not change logical sample positions.
			for seq := len(p.Samples) - 1; seq >= 0; seq-- {
				p.Samples[seq].MarkSent(100)
				if mass && seq%7 == 0 {
					wantDF[seq], wantIPID[seq] = "-", "-"
					continue
				}
				df := seq%3 == 0
				if df {
					wantDF[seq] = "1"
				} else {
					wantDF[seq] = "0"
				}
				wantIPID[seq] = "42"
				if !p.Samples[seq].TryFill(42, int64(200+seq), df) {
					t.Fatal("sample rejected")
				}
			}
			if variant == "connection" {
				// Replace the direct sample fills with actual SYN-ACK/data validation.
				measurement.TcpEstablishConnection = true
				p.Samples = make([]Sample, 16)
				for seq := uint16(0); seq < 16; seq++ {
					p.Samples[seq].MarkSent(100)
					flags := types.AckFlagSet
					if seq < 4 {
						flags = types.SynAckFlagSet
					}
					serverSequence := uint32(2001)
					if seq < 4 {
						serverSequence = 2000
					}
					if !FulfillReply(key, sender.GetSender(seq).IPBytes, 40000+seq%4, 1001+uint32(seq%4+seq/4), serverSequence, 42, flags, 200, 0, seq%3 == 0) {
						t.Fatalf("connection reply %d rejected", seq)
					}
				}
			}
			record, ok := probeToRecord(p, rt)
			if !ok || record.DFSequence != strings.Join(wantDF, ",") || record.IPIDSequence != strings.Join(wantIPID, ",") {
				t.Fatalf("misaligned DF/IPID record: %+v", record)
			}
			measurement.Paths.MeasurementFilePath = filepath.Join(t.TempDir(), "ipid.pq")
			SaveProbesChannel = make(chan *Probe, 1)
			SaveProbesChannel <- p
			close(SaveProbesChannel)
			measurement.SaveWg.Add(1)
			Save()
			if interprotocol {
				rows, err := parquet.ReadFile[records.InterProtocolRecord](measurement.Paths.MeasurementFilePath)
				if err != nil || len(rows) != 1 || rows[0].DFSequence != record.DFSequence || rows[0].IPIDSequence != record.IPIDSequence || rows[0].Strategy != "SINGLE" {
					t.Fatalf("interprotocol DF lost: rows=%+v err=%v", rows, err)
				}
			} else {
				rows, err := parquet.ReadFile[records.IPIDRecord](measurement.Paths.MeasurementFilePath)
				if err != nil || !reflect.DeepEqual(rows, []records.IPIDRecord{record}) {
					t.Fatalf("DF lost in Parquet: rows=%+v err=%v", rows, err)
				}
			}
			// Projection used by consumers that predate DF must still work.
			legacy, err := parquet.ReadFile[struct {
				IPAddress string `parquet:"IP_ADDR"`
				Sequence  string `parquet:"IPID_SEQUENCE"`
			}](measurement.Paths.MeasurementFilePath)
			if err != nil || len(legacy) != 1 || legacy[0].Sequence != record.IPIDSequence {
				t.Fatalf("legacy projection failed: %v", err)
			}
		})
	}
}
