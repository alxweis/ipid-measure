package probe

import (
	"bufio"
	"github.com/alxweis/ipid-measure/internal/consts"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"

	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
)

const (
	batchSize          = 20000
	maxRowsPerRowGroup = 2_000_000
	pageBufferSize     = 1 * 1024 * 1024
	valueSeparator     = ','
	invalidSymbol      = '-'
)

func SetupSaveChannel() {
	SaveProbesChannel = make(chan *Probe, consts.IPIDSaveChannelSize)
}

func CloseSaveChannel() {
	close(SaveProbesChannel)
}

func Save() {
	defer measurement.SaveWg.Done()

	f, err := os.Create(measurement.Paths.MeasurementFilePath)
	if err != nil {
		log.Fatalf("create parquet file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("file close error: %v", err)
		}
	}()

	bw := bufio.NewWriterSize(f, consts.IPIDSaveFileBufferSize)

	writer := parquet.NewGenericWriter[records.IPIDRecord](bw,
		parquet.Compression(&snappy.Codec{}),
		parquet.PageBufferSize(pageBufferSize),
		parquet.MaxRowsPerRowGroup(maxRowsPerRowGroup),
	)

	batch := make([]records.IPIDRecord, 0, batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if _, err := writer.Write(batch); err != nil {
			log.Printf("parquet write error: %v", err)
		}
		batch = batch[:0]
	}

	rtBased := measurement.Config.MeasurementMode == types.MeasurementModeRTBased

	for p := range SaveProbesChannel {
		if p == nil {
			continue
		}
		rec, ok := probeToRecord(p, rtBased)
		if !ok {
			// Skip malformed probes rather than aborting the whole measurement.
			continue
		}
		batch = append(batch, rec)
		if len(batch) >= batchSize {
			flush()
		}
	}

	// Final flush, then close writer and buffered writer in order.
	flush()
	if err := writer.Close(); err != nil {
		log.Printf("parquet close error: %v", err)
	}
	if err := bw.Flush(); err != nil {
		log.Printf("bufio flush error: %v", err)
	}
}

func probeToRecord(p *Probe, rtBased bool) (records.IPIDRecord, bool) {
	n := int(measurement.RequestCount)

	if len(p.Samples) != n {
		return records.IPIDRecord{}, false
	}

	// Preallocate builders: ipId up to 5 chars + comma; timestamps up to 16.
	var ipIds, sent, recv strings.Builder
	ipIds.Grow(n * 6)
	sent.Grow(n * 17)
	recv.Grow(n * 17)

	for seqNum := 0; seqNum < n; seqNum++ {
		r := &p.Samples[seqNum]
		received := r.IsReceived()

		if rtBased && !received {
			// In RT-based mode every sample must be valid by construction.
			return records.IPIDRecord{}, false
		}

		if seqNum > 0 {
			ipIds.WriteByte(valueSeparator)
			sent.WriteByte(valueSeparator)
			recv.WriteByte(valueSeparator)
		}

		if received {
			ipIds.WriteString(strconv.FormatUint(uint64(r.IpID), 10))
			sent.WriteString(strconv.FormatInt(r.SentTime, 10))
			recv.WriteString(strconv.FormatInt(r.ReceiveTime, 10))
		} else {
			ipIds.WriteByte(invalidSymbol)
			sent.WriteByte(invalidSymbol)
			recv.WriteByte(invalidSymbol)
		}
	}

	return records.IPIDRecord{
		IPAddress:                p.Target.To4().String(),
		IPIDSequence:             ipIds.String(),
		SendTimestampSequence:    sent.String(),
		ReceiveTimestampSequence: recv.String(),
	}, true
}

func init() {
	measurement.SetupSaveChannel = SetupSaveChannel
	measurement.StartSaver = func() { go Save() }
	measurement.CloseSaveChan = CloseSaveChannel
}
