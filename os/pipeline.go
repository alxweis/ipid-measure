package os

import (
	"context"
	"fmt"
	"io"
	"log"
	osstd "os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/records"
)

const (
	ZGrab2Binary          = "zgrab2"
	ZDNSBinary            = "zdns"
	ResultBufferSize      = 100_000
	ShutdownGraceSeconds  = 5
	StdoutReadBufferBytes = 1 << 20
)

// runPipeline reads IPs from zmap.pq, fans out to the three scanners,
// merges per-IP results, fingerprints, and writes to os.pq.
func runPipeline(ctx context.Context, c *config.OSConfig, zmapInputPath, outputPath string) (uint64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Open zmap
	inFile, err := osstd.Open(zmapInputPath)
	if err != nil {
		return 0, fmt.Errorf("open zmap input %s: %w", zmapInputPath, err)
	}
	defer inFile.Close()
	pqReader := parquet.NewGenericReader[records.ZMap](inFile)
	defer pqReader.Close()
	numberOfTargets := uint64(pqReader.NumRows())

	useZGrab2 := config.HasCoreZGrab2Module(c.Modules) ||
		(config.HasSecondaryZGrab2Module(c.Modules) && c.SecondarySampleRate > 0)
	useZDNS := config.HasZDNSModule(c.Modules) && c.SecondarySampleRate > 0
	useSNMP := config.HasSNMPModule(c.Modules)

	// Build subprocess args & write ZGrab2 ini
	iniPath := ""
	if useZGrab2 {
		ini := BuildZGrab2INI(
			c.Modules,
			*c.ZGrab2Senders,
			c.ConnectTimeout,
			c.ReadTimeout,
			c.SecondarySampleRate,
		)
		iniPath = osstd.TempDir() + "/ipid-zgrab2-" + fmt.Sprint(osstd.Getpid()) + ".ini"
		if err := WriteIniFile(ini, iniPath); err != nil {
			return 0, fmt.Errorf("write ini: %w", err)
		}
		defer func() { _ = osstd.Remove(iniPath) }()
	}

	// Start the writer + merger
	writer, err := NewWriter(outputPath)
	if err != nil {
		return 0, err
	}
	defer func() {
		if cerr := writer.Close(); cerr != nil {
			log.Printf("os: parquet close: %v", cerr)
		}
	}()

	outRecords := make(chan records.OSRecord, ResultBufferSize)
	m := newMerger(c, outRecords)
	writerErrCh := make(chan error, 1)
	selectionStats := &secondarySelectionStats{}

	// Writer goroutine: drains outRecords -> parquet.
	writerWg := sync.WaitGroup{}
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		if err := drainWriter(outRecords, writer.Append, cancel); err != nil {
			writerErrCh <- fmt.Errorf("append os parquet: %w", err)
		}
	}()

	// Start the three scanners
	var (
		zGrab2Runner *ZGrab2Runner
		zDnsRunner   *ZDNSRunner
		snmpProbe    *SNMPProbe
	)

	zGrab2In := make(chan string, 4096)
	zDnsIn := make(chan string, 4096)
	snmpIn := make(chan string, 4096)
	var snmpOut <-chan SNMPResult

	scannerWg := sync.WaitGroup{}

	if useZGrab2 {
		zGrab2Runner, err = StartZGrab2(ctx, ZGrab2Binary, iniPath)
		if err != nil {
			close(outRecords)
			writerWg.Wait()
			return writer.Written(), fmt.Errorf("start zgrab2: %w", err)
		}
		// Feed IP addresses into ZGrab2 stdin.
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			defer zGrab2Runner.Stdin().Close()
			writeOK := true
			for ip := range zGrab2In {
				if !writeOK {
					continue // drain only
				}
				if _, err := io.WriteString(zGrab2Runner.Stdin(), ip+"\n"); err != nil {
					log.Printf("os: zgrab2 stdin write failed (%v); draining remaining IP addresses without sending them to zgrab2", err)
					writeOK = false
					m.markScannerDead(scannerZGrab2)
				}
			}
		}()
		// Drain stderr to log
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			drainPipe(zGrab2Runner.Stderr(), func(s string) { log.Printf("zgrab2: %s", s) })
		}()
		// Parse stdout JSON-lines, route into merger
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			ch := make(chan ZGrab2Result, 256)
			done := make(chan struct{})
			go func() {
				if err := ParseZGrab2Stream(zGrab2Runner.Stdout(), ch); err != nil {
					log.Printf("zgrab2 parse: %v", err)
				}
				close(ch)
				close(done)
			}()
			for r := range ch {
				m.integrate(r.IP, scannerZGrab2, applyZGrab2(r))
			}
			<-done
		}()
	} else {
		// Even when ZGrab2 is disabled we still need to drain zGrab2In so the fan-out goroutine doesn't block.
		go func() {
			for range zGrab2In {
			}
		}()
	}

	if useZDNS {
		zDnsRunner, err = StartZDNS(ctx, ZDNSBinary, *c.ZDNSThreads, c.ReadTimeout)
		if err != nil {
			close(outRecords)
			writerWg.Wait()
			if zGrab2Runner != nil {
				_ = zGrab2Runner.Shutdown()
			}
			return writer.Written(), fmt.Errorf("start zdns: %w", err)
		}
		// Feed two CHAOS queries per IP. Same self-protecting pattern as the ZGrab2 feeder above:
		// if the subprocess dies, keep draining zDnsIn so the upstream feeder does not block.
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			defer zDnsRunner.Stdin().Close()
			writeOK := true
			for ip := range zDnsIn {
				if !writeOK {
					continue
				}
				if _, err := io.WriteString(zDnsRunner.Stdin(), ZDNSInputLine("version.bind", ip)); err != nil {
					log.Printf("os: zdns stdin write failed (%v); draining remaining IPs", err)
					writeOK = false
					m.markScannerDead(scannerZDNS)
					continue
				}
				if _, err := io.WriteString(zDnsRunner.Stdin(), ZDNSInputLine("hostname.bind", ip)); err != nil {
					log.Printf("os: zdns stdin write failed (%v); draining remaining IPs", err)
					writeOK = false
					m.markScannerDead(scannerZDNS)
				}
			}
		}()
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			drainPipe(zDnsRunner.Stderr(), func(s string) { log.Printf("zdns: %s", s) })
		}()
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			ch := make(chan ZDNSResult, 256)
			done := make(chan struct{})
			go func() {
				if err := ParseZDNSStream(zDnsRunner.Stdout(), ch); err != nil {
					log.Printf("zdns parse: %v", err)
				}
				close(ch)
				close(done)
			}()
			for r := range ch {
				m.integrate(r.IP, scannerZDNS, applyZDNS(r))
			}
			<-done
		}()
	} else {
		go func() {
			for range zDnsIn {
			}
		}()
	}

	if useSNMP {
		snmpProbe = NewSNMPProbe(c.SNMPCommunity, c.SNMPTimeout)
		snmpOut = snmpProbe.Run(ctx, snmpIn, int(*c.SNMPWorkers))
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			for r := range snmpOut {
				m.integrate(r.IP, scannerSNMP, applySNMP(r))
			}
		}()
	} else {
		go func() {
			for range snmpIn {
			}
		}()
	}

	// Feed IPs from parquet into all scanners
	feederErrCh := make(chan error, 1)
	send := func(ch chan<- string, ip string) bool {
		select {
		case ch <- ip:
			return true
		case <-ctx.Done():
			return false
		}
	}
	// Hoist scan-plan flags out of the per-IP loop.
	hasSecondary := config.HasSecondaryModule(c.Modules)
	tagSecondaryZGrab2 := config.HasSecondaryZGrab2Module(c.Modules) &&
		c.SecondarySampleRate > 0 && c.SecondarySampleRate < 1
	go func() {
		defer close(zGrab2In)
		defer close(zDnsIn)
		defer close(snmpIn)
		buf := make([]records.ZMap, consts.ZMapReadBufferSize)
		for {
			select {
			case <-ctx.Done():
				feederErrCh <- ctx.Err()
				return
			default:
			}
			n, err := pqReader.Read(buf)
			for i := 0; i < n; i++ {
				ip := buf[i].IPAddress
				if ip == "" {
					continue
				}
				selectedSecondary := hasSecondary &&
					selectSecondary(ip, c.SecondarySampleRate)
				if hasSecondary {
					if selectedSecondary {
						selectionStats.selected.Add(1)
					} else {
						selectionStats.skipped.Add(1)
					}
				}
				if useZGrab2 {
					input := zgrab2InputLine(
						ip,
						tagSecondaryZGrab2 && selectedSecondary,
					)
					if !send(zGrab2In, input) {
						feederErrCh <- ctx.Err()
						return
					}
				}
				if useZDNS {
					if selectedSecondary {
						if !send(zDnsIn, ip) {
							feederErrCh <- ctx.Err()
							return
						}
					} else {
						// Mark deliberately unsampled DNS as complete for
						// this IP without issuing either network query.
						m.integrate(ip, scannerZDNS, func(*records.OSRecord) {})
					}
				}
				if useSNMP {
					if !send(snmpIn, ip) {
						feederErrCh <- ctx.Err()
						return
					}
				}
			}
			if err != nil {
				if err == io.EOF {
					feederErrCh <- nil
					return
				}
				feederErrCh <- err
				return
			}
		}
	}()

	// Stats reporter (once per second)
	statsDone := make(chan struct{})
	go reportOSStats(ctx, m, writer, selectionStats, numberOfTargets, statsDone)

	// Wait for feeder + scanners + merger to drain
	feederErr := <-feederErrCh

	// Wait for all scanner goroutines
	scannerWg.Wait()

	// Wait for the external subprocesses to exit.
	if zGrab2Runner != nil {
		if ctx.Err() != nil {
			_ = zGrab2Runner.Shutdown()
		} else {
			if err := zGrab2Runner.Wait(); err != nil {
				log.Printf("zgrab2 exited: %v", err)
			}
		}
	}
	if zDnsRunner != nil {
		if ctx.Err() != nil {
			_ = zDnsRunner.Shutdown()
		} else {
			if err := zDnsRunner.Wait(); err != nil {
				log.Printf("zdns exited: %v", err)
			}
		}
	}

	// Force-emit any pending merger entries.
	m.flushAll()

	// Now close the writer's input channel and wait for the writer drain.
	close(outRecords)
	writerWg.Wait()

	// Stop the stats' reporter.
	close(statsDone)

	// Close the writer here so Written() reflects the final flushed row count
	// (the defer at function entry is now a no-op via Writer.closed).
	closeErr := writer.Close()

	log.Printf("os: wrote %d records, %d dropped (no OS match), %d merger inputs",
		m.totalEmitted.Load(), m.totalDropped.Load(), m.totalReceived.Load())

	select {
	case writerErr := <-writerErrCh:
		return writer.Written(), writerErr
	default:
	}
	if closeErr != nil {
		return writer.Written(), fmt.Errorf("close os parquet: %w", closeErr)
	}
	return writer.Written(), feederErr
}

// drainWriter keeps consuming records after the first write failure so merger
// goroutines cannot deadlock on a full output channel while cancellation drains
// the rest of the pipeline.
func drainWriter(
	records <-chan records.OSRecord,
	appendRecord func(records.OSRecord) error,
	cancel context.CancelFunc,
) error {
	var firstErr error
	for rec := range records {
		if firstErr != nil {
			continue
		}
		if err := appendRecord(rec); err != nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

type secondarySelectionStats struct {
	selected atomic.Uint64
	skipped  atomic.Uint64
}

// reportOSStats logs progress once per second so a long run shows life.
func reportOSStats(
	ctx context.Context,
	m *merger,
	w *Writer,
	selection *secondarySelectionStats,
	numberOfTargets uint64,
	done <-chan struct{},
) {
	t := time.NewTicker(consts.LogUpdateInterval)
	defer t.Stop()
	var lastCompleted uint64
	var ms runtime.MemStats
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-t.C:
			emitted := m.totalEmitted.Load()
			dropped := m.totalDropped.Load()
			completed := emitted + dropped
			deltaCompleted := completed - lastCompleted
			lastCompleted = completed
			received := m.totalReceived.Load()
			elapsed := time.Since(start).Truncate(time.Second)
			progress := 0.0
			eta := "warming-up"
			if numberOfTargets > 0 {
				progress = float64(completed) / float64(numberOfTargets) * 100
			}
			if completed > 0 && completed < numberOfTargets {
				remaining := time.Duration(
					float64(elapsed) / float64(completed) *
						float64(numberOfTargets-completed),
				).Truncate(time.Second)
				eta = remaining.String()
			} else if completed >= numberOfTargets && numberOfTargets > 0 {
				eta = "0s"
			}
			runtime.ReadMemStats(&ms)
			log.Printf("os: completed=%d/%d (%.2f%% +%d/s eta=%s) emitted=%d dropped=%d merger_in=%d (zgrab2=%d zdns=%d snmp=%d) secondary=(selected=%d skipped=%d) written=%d heap=%dMB goroutines=%d elapsed=%s",
				completed, numberOfTargets, progress, deltaCompleted, eta,
				emitted, dropped, received,
				m.rxZGrab2.Load(), m.rxZDNS.Load(), m.rxSNMP.Load(),
				selection.selected.Load(), selection.skipped.Load(),
				w.Written(), ms.HeapAlloc>>20, runtime.NumGoroutine(), elapsed)
		}
	}
}
