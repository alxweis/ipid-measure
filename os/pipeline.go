package os

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	osstd "os"
	"runtime"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/records"
)

const (
	ZGrab2Binary          = "zgrab2"
	ResultBufferSize      = 100_000
	ShutdownGraceSeconds  = 5
	StdoutReadBufferBytes = 1 << 20
	ScannerInputBuffer    = 4096
)

// runPipeline scans every input IP with SSH, SMB, HTTP, HTTPS, SNMP and DNS
// CHAOS. The three scanner implementations run concurrently with bounded
// queues; the merger writes a row only when at least one evidence string exists.
func runPipeline(
	ctx context.Context,
	c *config.OSConfig,
	zmapInputPath, outputPath, coveragePath string,
) (uint64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	inFile, err := osstd.Open(zmapInputPath)
	if err != nil {
		return 0, fmt.Errorf("open zmap input %s: %w", zmapInputPath, err)
	}
	defer inFile.Close()
	pqReader := parquet.NewGenericReader[records.ZMap](inFile)
	defer pqReader.Close()
	numberOfTargets := uint64(pqReader.NumRows())

	ini := BuildZGrab2INI(c.Modules, *c.ZGrab2Senders, c.ConnectTimeout, c.ReadTimeout)
	iniPath := osstd.TempDir() + "/ipid-zgrab2-" + fmt.Sprint(osstd.Getpid()) + ".ini"
	if err := WriteIniFile(ini, iniPath); err != nil {
		return 0, fmt.Errorf("write zgrab2 ini: %w", err)
	}
	defer func() { _ = osstd.Remove(iniPath) }()

	zgrab, err := StartZGrab2(ctx, ZGrab2Binary, iniPath)
	if err != nil {
		return 0, fmt.Errorf("start zgrab2: %w", err)
	}

	writer, err := NewWriter(outputPath)
	if err != nil {
		_ = zgrab.Shutdown()
		return 0, err
	}
	coverage := newCoverageStats(numberOfTargets)
	outRecords := make(chan records.OSRecord, ResultBufferSize)
	m := newMerger(outRecords, coverage)

	writerErrCh := make(chan error, 1)
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		if err := drainWriter(outRecords, writer.Append, cancel); err != nil {
			writerErrCh <- fmt.Errorf("append os parquet: %w", err)
		}
	}()

	zgrabIn := make(chan string, ScannerInputBuffer)
	dnsIn := make(chan string, ScannerInputBuffer)
	snmpIn := make(chan string, ScannerInputBuffer)
	dnsOut := NewDNSChaosProbe(c.ReadTimeout).Run(ctx, dnsIn, int(*c.DNSChaosWorkers))
	snmpOut := NewSNMPProbe(c.SNMPCommunity, c.SNMPTimeout).Run(ctx, snmpIn, int(*c.SNMPWorkers))

	scannerErrCh := make(chan error, 4)
	reportScannerError := func(err error) {
		if err == nil {
			return
		}
		select {
		case scannerErrCh <- err:
		default:
		}
		cancel()
	}

	var scannerWg sync.WaitGroup
	scannerWg.Add(5)
	go func() {
		defer scannerWg.Done()
		defer zgrab.Stdin().Close()
		for ip := range zgrabIn {
			if _, err := io.WriteString(zgrab.Stdin(), ip+"\n"); err != nil {
				reportScannerError(fmt.Errorf("write zgrab2 input: %w", err))
				return
			}
		}
	}()
	go func() {
		defer scannerWg.Done()
		drainPipe(zgrab.Stderr(), func(line string) { log.Printf("zgrab2: %s", line) })
	}()
	go func() {
		defer scannerWg.Done()
		results := make(chan ZGrab2Result, 256)
		parseDone := make(chan error, 1)
		go func() {
			parseDone <- ParseZGrab2Stream(zgrab.Stdout(), results)
			close(results)
		}()
		for result := range results {
			m.integrate(result.IP, scannerZGrab2, applyZGrab2(result))
		}
		reportScannerError(<-parseDone)
	}()
	go func() {
		defer scannerWg.Done()
		for result := range dnsOut {
			m.integrate(result.IP, scannerDNSChaos, applyDNSChaos(result))
		}
	}()
	go func() {
		defer scannerWg.Done()
		for result := range snmpOut {
			m.integrate(result.IP, scannerSNMP, applySNMP(result))
		}
	}()

	feederErrCh := make(chan error, 1)
	go func() {
		defer close(zgrabIn)
		defer close(dnsIn)
		defer close(snmpIn)
		feederErrCh <- feedTargets(ctx, pqReader, zgrabIn, dnsIn, snmpIn)
	}()

	statsDone := make(chan struct{})
	go reportOSStats(ctx, m, writer, numberOfTargets, statsDone)
	feederErr := <-feederErrCh
	scannerWg.Wait()

	var zgrabErr error
	if ctx.Err() != nil {
		zgrabErr = zgrab.Shutdown()
	} else {
		zgrabErr = zgrab.Wait()
	}
	close(outRecords)
	writerWg.Wait()
	close(statsDone)
	closeErr := writer.Close()

	var scannerErr error
	select {
	case scannerErr = <-scannerErrCh:
	default:
	}
	var writerErr error
	select {
	case writerErr = <-writerErrCh:
	default:
	}

	if writerErr != nil {
		return writer.Written(), writerErr
	}
	if scannerErr != nil {
		return writer.Written(), scannerErr
	}
	if feederErr != nil && !errors.Is(feederErr, context.Canceled) {
		return writer.Written(), fmt.Errorf("feed OS targets: %w", feederErr)
	}
	if ctx.Err() != nil {
		return writer.Written(), ctx.Err()
	}
	if zgrabErr != nil {
		return writer.Written(), fmt.Errorf("zgrab2 exited: %w", zgrabErr)
	}
	if closeErr != nil {
		return writer.Written(), fmt.Errorf("close os parquet: %w", closeErr)
	}
	if pending := m.pendingCount(); pending != 0 {
		return writer.Written(), fmt.Errorf("OS merger incomplete: %d targets missing scanner results", pending)
	}
	if completed := m.totalEmitted.Load() + m.totalDropped.Load(); completed != numberOfTargets {
		return writer.Written(), fmt.Errorf("OS pipeline completed %d of %d targets", completed, numberOfTargets)
	}
	if err := coverage.write(coveragePath); err != nil {
		return writer.Written(), err
	}

	log.Printf("os: wrote %d evidence records; %d targets had no evidence",
		m.totalEmitted.Load(), m.totalDropped.Load())
	return writer.Written(), nil
}

func feedTargets(
	ctx context.Context,
	reader *parquet.GenericReader[records.ZMap],
	zgrabIn, dnsIn, snmpIn chan<- string,
) error {
	send := func(channel chan<- string, ip string) bool {
		select {
		case channel <- ip:
			return true
		case <-ctx.Done():
			return false
		}
	}
	buffer := make([]records.ZMap, consts.ZMapReadBufferSize)
	for {
		n, err := reader.Read(buffer)
		for i := 0; i < n; i++ {
			ip := buffer[i].IPAddress
			if ip == "" {
				continue
			}
			if !send(zgrabIn, ip) || !send(dnsIn, ip) || !send(snmpIn, ip) {
				return ctx.Err()
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func drainWriter(
	input <-chan records.OSRecord,
	appendRecord func(records.OSRecord) error,
	cancel context.CancelFunc,
) error {
	var firstErr error
	for record := range input {
		if firstErr != nil {
			continue
		}
		if err := appendRecord(record); err != nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

func reportOSStats(
	ctx context.Context,
	m *merger,
	w *Writer,
	numberOfTargets uint64,
	done <-chan struct{},
) {
	ticker := time.NewTicker(consts.LogUpdateInterval)
	defer ticker.Stop()
	var lastCompleted uint64
	var memory runtime.MemStats
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			emitted := m.totalEmitted.Load()
			dropped := m.totalDropped.Load()
			completed := emitted + dropped
			delta := completed - lastCompleted
			lastCompleted = completed
			progress := 0.0
			if numberOfTargets > 0 {
				progress = float64(completed) / float64(numberOfTargets) * 100
			}
			runtime.ReadMemStats(&memory)
			log.Printf("os: completed=%d/%d (%.2f%% +%d/s) written=%d pending=%d scanner_results=(zgrab2=%d dns=%d snmp=%d) heap=%dMB goroutines=%d elapsed=%s",
				completed, numberOfTargets, progress, delta, w.Written(), m.pendingCount(),
				m.rxZGrab2.Load(), m.rxDNSChaos.Load(), m.rxSNMP.Load(),
				memory.HeapAlloc>>20, runtime.NumGoroutine(), time.Since(start).Truncate(time.Second))
		}
	}
}
