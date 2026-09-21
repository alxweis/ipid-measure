package probe

import (
	"bytes"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/parquet-go/parquet-go"
)

func TestCaptureTimestampRTTBounds(t *testing.T) {
	for _, variant := range []struct {
		name   string
		mode   types.MeasurementMode
		strict bool
	}{
		{"rt-base", types.MeasurementModeRTBased, true},
		{"fixed-base", types.MeasurementModeFixedInterval, true},
		{"mass", types.MeasurementModeFixedInterval, false},
	} {
		for _, test := range []struct {
			name string
			rtt  time.Duration
			ok   bool
		}{
			{"before-send", -time.Microsecond, false},
			{"same-microsecond", 0, true},
			{"queued-on-time", 20 * time.Millisecond, true},
			{"at-limit", time.Second, true},
			{"late", time.Second + time.Microsecond, false},
		} {
			t.Run(variant.name+"/"+test.name, func(t *testing.T) {
				p, key := baseFixture(t)
				p.strict = variant.strict
				measurement.Config.MeasurementMode = variant.mode
				sent := time.Unix(1700000000, 123456000).UnixMicro()
				p.Samples[0].MarkSent(sent)
				received := sent + test.rtt.Microseconds()
				counter := &stats.DropLate
				if test.rtt < 0 {
					counter = &stats.DropUnsent
				}
				before := atomic.LoadInt64(counter)
				got := FulfillReply(key, sender.SenderA.IPBytes, 40000, 0, 2000, 42, types.SynAckFlagSet, received, 0)
				if got != test.ok || p.Samples[0].IsReceived() != test.ok {
					t.Fatalf("reply accepted = %v, want %v", got, test.ok)
				}
				if test.ok {
					if p.Samples[0].ReceiveTime != received {
						t.Fatal("capture timestamp replaced with processing time")
					}
				} else {
					if atomic.LoadInt64(counter) != before+1 {
						t.Fatal("wrong timestamp rejection counter")
					}
					if variant.strict && p.complete() {
						t.Fatal("invalid capture timestamp did not abort Base")
					}
					if !variant.strict && !p.complete() {
						t.Fatal("invalid capture timestamp aborted Mass")
					}
				}
			})
		}
	}
}

func TestCaptureTimestampsPreservedInParquet(t *testing.T) {
	for _, rt := range []bool{false, true} {
		t.Run(strconv.FormatBool(rt), func(t *testing.T) {
			p, key := baseFixture(t)
			if rt {
				measurement.Config.MeasurementMode = types.MeasurementModeRTBased
			}
			start := time.Unix(1700000000, 123456000).UnixMicro()
			want := make([]string, len(p.Samples))
			for seq := range p.Samples {
				sent := start + int64(seq)*50000
				received := sent + 10000
				if !rt {
					sent = start
					received = start + int64(len(p.Samples)-seq)*1000
				}
				p.Samples[seq].MarkSent(sent)
				if !FulfillReply(key, sender.GetSender(uint16(seq)).IPBytes, 40000+uint16(seq)%4, uint32(seq), 2000, uint16(seq), types.SynAckFlagSet, received, 0) {
					t.Fatalf("reply %d rejected", seq)
				}
				want[seq] = strconv.FormatInt(received, 10)
			}
			if !p.complete() {
				t.Fatal("complete probe rejected")
			}
			record, ok := probeToRecord(p, rt)
			if !ok {
				t.Fatal("record rejected")
			}
			var buffer bytes.Buffer
			writer := parquet.NewGenericWriter[records.IPIDRecord](&buffer)
			if _, err := writer.Write([]records.IPIDRecord{record}); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			rows, err := parquet.Read[records.IPIDRecord](bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].ReceiveTimestampSequence != strings.Join(want, ",") {
				t.Fatal("Parquet changed capture times or reordered samples")
			}
		})
	}
}

func TestCaptureTimestampDoesNotReviveTimedOutBase(t *testing.T) {
	p, key := baseFixture(t)
	p.Samples[0].MarkSent(100)
	p.fail(&stats.DropTimeout)
	if reply(t, key, 0, types.SynAckFlagSet) || p.Samples[0].IsReceived() || p.complete() {
		t.Fatal("on-time capture revived a timed-out probe")
	}
}
