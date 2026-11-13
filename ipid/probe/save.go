package probe

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/alxweis/ipid-measure/internal/consts"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"

	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/rtresume"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/stats"
)

const (
	ParquetWriteBatchSize     = 10_000
	ParquetMaxRowsPerRowGroup = 50_000
	ParquetPageBufferBytes    = 1 << 20
	ValueSeparator            = ','
	InvalidSymbol             = '-'
)

var saveReady chan error

func signalSaveReady(err error) {
	// Direct writer tests/callers may provide their own closed save channel;
	// the normal measurement lifecycle always calls SetupSaveChannel first.
	if saveReady != nil {
		saveReady <- err
	}
}

func SetupSaveChannel() {
	SaveProbesChannel = make(chan *Probe, consts.IPIDSaveChannelSize)
	saveReady = make(chan error, 1)
}

func CloseSaveChannel() {
	close(SaveProbesChannel)
}

func Save() {
	defer measurement.SaveWg.Done()

	var f *os.File
	var err error
	if measurement.ResumePlan != nil {
		f, err = os.OpenFile(measurement.Paths.MeasurementFilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	} else {
		f, err = os.Create(measurement.Paths.MeasurementFilePath)
	}
	if err != nil {
		signalSaveReady(err)
		measurement.Fail(fmt.Errorf("create ipid parquet file: %w", err))
		for range SaveProbesChannel {
		}
		return
	}

	bw := bufio.NewWriterSize(f, consts.IPIDSaveFileBufferSize)

	if measurement.IsInterProtocol() {
		signalSaveReady(nil)
		saveInterProtocol(bw, f)
		return
	}

	writer := parquet.NewGenericWriter[records.IPIDRecord](bw,
		parquet.Compression(&snappy.Codec{}),
		parquet.PageBufferSize(ParquetPageBufferBytes),
		parquet.MaxRowsPerRowGroup(ParquetMaxRowsPerRowGroup),
	)

	batch := make([]records.IPIDRecord, 0, ParquetWriteBatchSize)
	failed := false
	if plan := measurement.ResumePlan; plan != nil {
		if err := rtresume.Copy(plan, writer, measurement.StopSignal); err != nil {
			failed = true
			measurement.Fail(fmt.Errorf("copy retained RT results: %w", err))
			signalSaveReady(err)
		} else if err := bw.Flush(); err != nil {
			failed = true
			measurement.Fail(err)
			signalSaveReady(err)
		} else {
			atomic.StoreInt64(&stats.ValidProbes, plan.Saved)
			atomic.StoreInt64(&stats.ProbeCount, plan.Started)
			stats.RestoreTerminalFailures(plan.Failures)
			log.Printf("RT recovery: retained %d successes and %d terminal failures; resume at target %d/%d. Reply/network diagnostics cover the resumed segment only.", plan.Saved, plan.Started-plan.Saved, plan.Started, plan.Total)
			signalSaveReady(nil)
		}
	} else {
		signalSaveReady(nil)
	}

	flush := func() {
		if len(batch) == 0 || failed {
			return
		}
		if _, err := writer.Write(batch); err != nil {
			failed = true
			measurement.Fail(fmt.Errorf("write ipid parquet: %w", err))
		}
		batch = batch[:0]
	}

	rtBased := measurement.Config.MeasurementMode == types.MeasurementModeRTBased

	for p := range SaveProbesChannel {
		if p == nil || failed {
			continue
		}
		rec, ok := probeToRecord(p, rtBased)
		if !ok {
			// Skip malformed probes rather than aborting the whole measurement.
			continue
		}
		batch = append(batch, rec)
		if len(batch) >= ParquetWriteBatchSize {
			flush()
		}
	}

	// Final flush, then close writer and buffered writer in order.
	flush()
	if err := writer.Close(); err != nil {
		measurement.Fail(fmt.Errorf("close ipid parquet writer: %w", err))
	}
	if err := bw.Flush(); err != nil {
		measurement.Fail(fmt.Errorf("flush ipid parquet buffer: %w", err))
	}
	if err := f.Close(); err != nil {
		measurement.Fail(fmt.Errorf("close ipid parquet file: %w", err))
	}
}

func saveInterProtocol(bw *bufio.Writer, f *os.File) {
	writer := parquet.NewGenericWriter[records.InterProtocolRecord](bw,
		parquet.Compression(&snappy.Codec{}),
		parquet.PageBufferSize(ParquetPageBufferBytes),
		parquet.MaxRowsPerRowGroup(ParquetMaxRowsPerRowGroup),
	)
	batch := make([]records.InterProtocolRecord, 0, ParquetWriteBatchSize)
	failed := false
	flush := func() {
		if len(batch) == 0 || failed {
			return
		}
		if _, err := writer.Write(batch); err != nil {
			failed = true
			measurement.Fail(fmt.Errorf("write interprotocol parquet: %w", err))
		}
		batch = batch[:0]
	}
	for p := range SaveProbesChannel {
		if p == nil || failed {
			continue
		}
		base, ok := probeToRecord(p, false)
		if !ok {
			continue
		}
		batch = append(batch, records.InterProtocolRecord{
			IPAddress: base.IPAddress, Strategy: p.TargetStrategy,
			IPIDSequence:             base.IPIDSequence,
			SendTimestampSequence:    base.SendTimestampSequence,
			ReceiveTimestampSequence: base.ReceiveTimestampSequence,
			DFSequence:               base.DFSequence,
		})
		if len(batch) >= ParquetWriteBatchSize {
			flush()
		}
	}
	flush()
	if err := writer.Close(); err != nil {
		measurement.Fail(fmt.Errorf("close interprotocol parquet writer: %w", err))
	}
	if err := bw.Flush(); err != nil {
		measurement.Fail(fmt.Errorf("flush interprotocol parquet buffer: %w", err))
	}
	if err := f.Close(); err != nil {
		measurement.Fail(fmt.Errorf("close interprotocol parquet file: %w", err))
	}
}

func probeToRecord(p *Probe, rtBased bool) (records.IPIDRecord, bool) {
	n := int(measurement.RequestCount)

	if len(p.Samples) != n {
		return records.IPIDRecord{}, false
	}

	// Preallocate builders: ipId up to 5 chars + comma; timestamps up to 16.
	var ipIds, sent, recv, df strings.Builder
	ipIds.Grow(n * 6)
	sent.Grow(n * 17)
	recv.Grow(n * 17)
	df.Grow(n * 2)

	for seqNum := 0; seqNum < n; seqNum++ {
		r := &p.Samples[seqNum]
		received := r.IsReceived()

		if rtBased && !received {
			// In RT-based mode every sample must be valid by construction.
			return records.IPIDRecord{}, false
		}

		if seqNum > 0 {
			ipIds.WriteByte(ValueSeparator)
			sent.WriteByte(ValueSeparator)
			recv.WriteByte(ValueSeparator)
			df.WriteByte(ValueSeparator)
		}

		if received {
			ipIds.WriteString(strconv.FormatUint(uint64(r.IpID), 10))
			sent.WriteString(strconv.FormatInt(r.SentTime, 10))
			recv.WriteString(strconv.FormatInt(r.ReceiveTime, 10))
			if r.DontFragment {
				df.WriteByte('1')
			} else {
				df.WriteByte('0')
			}
		} else {
			ipIds.WriteByte(InvalidSymbol)
			sent.WriteByte(InvalidSymbol)
			recv.WriteByte(InvalidSymbol)
			df.WriteByte(InvalidSymbol)
		}
	}

	return records.IPIDRecord{
		IPAddress:                p.Target.To4().String(),
		IPIDSequence:             ipIds.String(),
		SendTimestampSequence:    sent.String(),
		ReceiveTimestampSequence: recv.String(),
		DFSequence:               df.String(),
	}, true
}

func init() {
	measurement.SetupSaveChannel = SetupSaveChannel
	measurement.StartSaver = func() { go Save() }
	measurement.WaitSaverReady = func() error { return <-saveReady }
	measurement.CloseSaveChan = CloseSaveChannel
}
