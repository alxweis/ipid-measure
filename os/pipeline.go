package os

import (
	"context"
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
	ZDNSBinary            = "zdns"
	ResultBufferSize      = 100_000
	ShutdownGraceSeconds  = 5
	StdoutReadBufferBytes = 1 << 20
)

// runPipeline reads IPs from zmap.pq, fans out to the three scanners,
// merges per-IP results, fingerprints, and writes to os.pq.
func runPipeline(ctx context.Context, c *config.OSConfig, zmapInputPath, outputPath string) (uint64, error) {
	// Open zmap
	inFile, err := osstd.Open(zmapInputPath)
	if err != nil {
		return 0, fmt.Errorf("open zmap input %s: %w", zmapInputPath, err)
	}
	defer inFile.Close()
	pqReader := parquet.NewGenericReader[records.ZMap](inFile)
	defer pqReader.Close()

	// Build subprocess args & write ZGrab2 ini
	iniPath := ""
	if config.HasZGrab2Module(c.Modules) {
		ini := BuildZGrab2INI(c.Modules, *c.ZGrab2Senders, c.ConnectTimeout, c.ReadTimeout)
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
	m := newMerger(c.Modules, outRecords)

	// Writer goroutine: drains outRecords -> parquet.
	writerWg := sync.WaitGroup{}
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for rec := range outRecords {
			if err := writer.Append(rec); err != nil {
				log.Printf("os: parquet append: %v", err)
				return
			}
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

	if config.HasZGrab2Module(c.Modules) {
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
			ts := time.Now().UnixMicro()
			for r := range ch {
				m.integrate(r.IP, scannerZGrab2, ts, applyZGrab2(r))
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

	if config.HasZDNSModule(c.Modules) {
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
			ts := time.Now().UnixMicro()
			for r := range ch {
				m.integrate(r.IP, scannerZDNS, ts, applyZDNS(r))
			}
			<-done
		}()
	} else {
		go func() {
			for range zDnsIn {
			}
		}()
	}

	if config.HasSNMPModule(c.Modules) {
		snmpProbe = NewSNMPProbe(c.SNMPCommunity, c.SNMPTimeout)
		snmpOut = snmpProbe.Run(ctx, snmpIn, int(*c.SNMPWorkers))
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			for r := range snmpOut {
				ts := time.Now().UnixMicro()
				m.integrate(r.IP, scannerSNMP, ts, applySNMP(r))
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
	// Hoist scanner-enabled flags out of the per-IP loop.
	useZGrab2 := config.HasZGrab2Module(c.Modules)
	useZDNS := config.HasZDNSModule(c.Modules)
	useSNMP := config.HasSNMPModule(c.Modules)
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
				if useZGrab2 {
					if !send(zGrab2In, ip) {
						feederErrCh <- ctx.Err()
						return
					}
				}
				if useZDNS {
					if !send(zDnsIn, ip) {
						feederErrCh <- ctx.Err()
						return
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
	go reportOSStats(ctx, m, writer, statsDone)

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
	if err := writer.Close(); err != nil {
		log.Printf("os: parquet close: %v", err)
	}

	log.Printf("os: wrote %d records, %d dropped (no OS match), %d merger inputs",
		m.totalEmitted.Load(), m.totalDropped.Load(), m.totalReceived.Load())

	return writer.Written(), feederErr
}

// reportOSStats logs progress once per second so a long run shows life.
func reportOSStats(ctx context.Context, m *merger, w *Writer, done <-chan struct{}) {
	t := time.NewTicker(consts.LogUpdateInterval)
	defer t.Stop()
	var lastEmitted uint64
	var ms runtime.MemStats
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-t.C:
			cur := m.totalEmitted.Load()
			delta := cur - lastEmitted
			lastEmitted = cur
			received := m.totalReceived.Load()
			dropped := m.totalDropped.Load()
			elapsed := time.Since(start).Truncate(time.Second)
			runtime.ReadMemStats(&ms)
			log.Printf("os: emitted=%d (+%d) dropped=%d merger_in=%d (zgrab2=%d zdns=%d snmp=%d) written=%d heap=%dMB goroutines=%d elapsed=%s",
				cur, delta, dropped, received,
				m.rxZGrab2.Load(), m.rxZDNS.Load(), m.rxSNMP.Load(),
				w.Written(), ms.HeapAlloc>>20, runtime.NumGoroutine(), elapsed)
		}
	}
}
