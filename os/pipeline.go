package os

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	osstd "os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/netd-tud/ipid-measure/internal/config"
	"github.com/netd-tud/ipid-measure/internal/consts"
	"github.com/netd-tud/ipid-measure/internal/records"
)

// runPipeline ties together: reading IPs from the zmap parquet input, fanning
// them out to the three scanners (zgrab2 / zdns / snmp), merging their
// per-IP results, fingerprinting, and writing to the OS parquet.
//
// Returns the number of records written (i.e. successfully-fingerprinted IPs)
// and the first error encountered (or nil on a clean run).
func runPipeline(ctx context.Context, cfg config.ResolvedOSConfig, zmapInputPath, outputPath string) (uint64, error) {
	// ---------- 0. Sanity: at least one scanner enabled ---------------
	enabled := enabledMask(cfg.Modules)
	if enabled == 0 {
		return 0, errors.New("no modules enabled in config")
	}

	// ---------- 1. Open the input parquet (responder IPs) -------------
	inFile, err := osstd.Open(zmapInputPath)
	if err != nil {
		return 0, fmt.Errorf("open zmap input %s: %w", zmapInputPath, err)
	}
	defer inFile.Close()
	pqReader := parquet.NewGenericReader[records.ZMap](inFile)
	defer pqReader.Close()

	// ---------- 2. Build subprocess args & write zgrab2 ini -----------
	iniPath := ""
	if (enabled & scannerZGrab2) != 0 {
		ini := BuildZGrab2INI(cfg.Modules, cfg.ZGrab2Senders, cfg.ConnectTimeout, cfg.ReadTimeout, cfg.Interface.IP)
		iniPath = osstd.TempDir() + "/ipid-zgrab2-" + fmt.Sprint(osstd.Getpid()) + ".ini"
		if err := WriteIniFile(ini, iniPath); err != nil {
			return 0, fmt.Errorf("write ini: %w", err)
		}
		defer func() { _ = osstd.Remove(iniPath) }()
	}

	// ---------- 3. Start the writer + merger ------------------------
	writer, err := NewWriter(outputPath)
	if err != nil {
		return 0, err
	}
	defer func() {
		if cerr := writer.Close(); cerr != nil {
			log.Printf("os: parquet close: %v", cerr)
		}
	}()

	outRecords := make(chan records.OSRecord, consts.OSResultBufferSize)
	m := newMerger(cfg.Modules, outRecords)

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

	// ---------- 4. Start the three scanners --------------------------
	var (
		zgrab2Runner *ZGrab2Runner
		zdnsRunner   *ZDNSRunner
		snmpProbe    *SNMPProbe
	)

	zgrab2In := make(chan string, 4096)
	zdnsIn := make(chan string, 4096)
	snmpIn := make(chan string, 4096)
	var snmpOut <-chan SNMPResult

	scannerWg := sync.WaitGroup{}

	if (enabled & scannerZGrab2) != 0 {
		zgrab2Runner, err = StartZGrab2(ctx, cfg.ZGrab2Binary, iniPath)
		if err != nil {
			close(outRecords)
			writerWg.Wait()
			return writer.Written(), fmt.Errorf("start zgrab2: %w", err)
		}
		// Feed IPs into zgrab2 stdin. Critical: if the subprocess has died
		// (broken pipe on write), we must KEEP draining zgrab2In so the
		// feeder does not block. We also signal the merger that no more
		// zgrab2 results are coming by marking the scanner as "done" on
		// the merger side.
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			defer zgrab2Runner.Stdin().Close()
			writeOK := true
			for ip := range zgrab2In {
				if !writeOK {
					continue // drain only
				}
				if _, err := io.WriteString(zgrab2Runner.Stdin(), ip+"\n"); err != nil {
					log.Printf("os: zgrab2 stdin write failed (%v); draining remaining IPs without sending them to zgrab2", err)
					writeOK = false
					m.markScannerDead(scannerZGrab2)
				}
			}
		}()
		// Drain stderr to log
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			drainPipe(zgrab2Runner.Stderr(), func(s string) { log.Printf("zgrab2: %s", s) })
		}()
		// Parse stdout JSON-lines, route into merger
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			ch := make(chan ZGrab2Result, 256)
			done := make(chan struct{})
			go func() {
				if err := ParseZGrab2Stream(zgrab2Runner.Stdout(), ch); err != nil {
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
		// Even when zgrab2 is disabled we still need to drain zgrab2In so the
		// fan-out goroutine doesn't block.
		go func() {
			for range zgrab2In {
			}
		}()
	}

	if (enabled & scannerZDNS) != 0 {
		zdnsRunner, err = StartZDNS(ctx, cfg.ZDNSBinary, cfg.ZDNSThreads, cfg.ReadTimeout)
		if err != nil {
			close(outRecords)
			writerWg.Wait()
			if zgrab2Runner != nil {
				_ = zgrab2Runner.Shutdown()
			}
			return writer.Written(), fmt.Errorf("start zdns: %w", err)
		}
		// Feed two CHAOS queries per IP. Same self-protecting pattern as
		// the zgrab2 feeder above: if the subprocess dies, keep draining
		// zdnsIn so the upstream feeder does not block.
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			defer zdnsRunner.Stdin().Close()
			writeOK := true
			for ip := range zdnsIn {
				if !writeOK {
					continue
				}
				if _, err := io.WriteString(zdnsRunner.Stdin(), ZDNSInputLine("version.bind", ip)); err != nil {
					log.Printf("os: zdns stdin write failed (%v); draining remaining IPs", err)
					writeOK = false
					m.markScannerDead(scannerZDNS)
					continue
				}
				if _, err := io.WriteString(zdnsRunner.Stdin(), ZDNSInputLine("hostname.bind", ip)); err != nil {
					log.Printf("os: zdns stdin write failed (%v); draining remaining IPs", err)
					writeOK = false
					m.markScannerDead(scannerZDNS)
				}
			}
		}()
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			drainPipe(zdnsRunner.Stderr(), func(s string) { log.Printf("zdns: %s", s) })
		}()
		scannerWg.Add(1)
		go func() {
			defer scannerWg.Done()
			ch := make(chan ZDNSResult, 256)
			done := make(chan struct{})
			go func() {
				if err := ParseZDNSStream(zdnsRunner.Stdout(), ch); err != nil {
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
			for range zdnsIn {
			}
		}()
	}

	if (enabled & scannerSNMP) != 0 {
		snmpProbe = NewSNMPProbe(cfg.SNMPCommunity, cfg.SNMPTimeout)
		snmpOut = snmpProbe.Run(ctx, snmpIn, int(cfg.SNMPWorkers))
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

	// ---------- 5. Feed IPs from parquet into all scanners -----------
	//
	// Each scanner has its own input channel. The feeder reads IPs from the
	// parquet, then sends them to every active scanner channel.
	//
	// Each send is wrapped in a select with ctx.Done(): if a scanner is dead
	// (e.g. zgrab2 died early) its goroutine will eventually close the
	// corresponding stdin pipe; until then a backpressured send could block
	// indefinitely. The ctx.Done() arm guarantees we exit on SIGINT/SIGTERM.
	//
	// We do NOT use individual fan-out goroutines per scanner because each
	// scanner needs EVERY IP -- a single master channel with multiple readers
	// would only deliver each IP to one of them (round-robin).
	feederErrCh := make(chan error, 1)
	send := func(ch chan<- string, ip string) bool {
		select {
		case ch <- ip:
			return true
		case <-ctx.Done():
			return false
		}
	}
	go func() {
		defer close(zgrab2In)
		defer close(zdnsIn)
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
				if (enabled & scannerZGrab2) != 0 {
					if !send(zgrab2In, ip) {
						feederErrCh <- ctx.Err()
						return
					}
				}
				if (enabled & scannerZDNS) != 0 {
					if !send(zdnsIn, ip) {
						feederErrCh <- ctx.Err()
						return
					}
				}
				if (enabled & scannerSNMP) != 0 {
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

	// ---------- 6. Stats reporter (once per second) -------------------
	statsDone := make(chan struct{})
	go reportOSStats(ctx, m, writer, statsDone)

	// ---------- 7. Wait for feeder + scanners + merger to drain ------
	feederErr := <-feederErrCh

	// Wait for all scanner goroutines: this naturally finishes once the
	// subprocesses have exited (their stdouts EOF), which only happens after
	// their stdins are closed (done by feeder goroutines above).
	scannerWg.Wait()

	// Wait for the SNMP probe pool to drain (its workers exited when snmpIn
	// closed). The snmpOut channel was already drained by the goroutine above
	// which is counted into scannerWg.

	// Wait for the external subprocesses to exit. If we started them, wait
	// for them; both have been signalled by closing their stdins. On
	// ctx-cancel (interrupt) we send SIGTERM/SIGKILL explicitly via Shutdown
	// rather than waiting for graceful exit, because the subprocess may
	// itself be stuck.
	if zgrab2Runner != nil {
		if ctx.Err() != nil {
			_ = zgrab2Runner.Shutdown()
		} else {
			if err := zgrab2Runner.Wait(); err != nil {
				log.Printf("zgrab2 exited: %v", err)
			}
		}
	}
	if zdnsRunner != nil {
		if ctx.Err() != nil {
			_ = zdnsRunner.Shutdown()
		} else {
			if err := zdnsRunner.Wait(); err != nil {
				log.Printf("zdns exited: %v", err)
			}
		}
	}

	// Force-emit any pending merger entries (IPs where one scanner produced
	// no output line at all).
	m.flushAll()

	// Now close the writer's input channel and wait for the writer drain.
	close(outRecords)
	writerWg.Wait()

	// Stop the stats reporter.
	close(statsDone)

	log.Printf("os: wrote %d records, %d dropped (no OS match), %d merger inputs",
		m.totalEmitted.Load(), m.totalDropped.Load(), m.totalReceived.Load())

	return writer.Written(), feederErr
}

// reportOSStats logs progress once per second so a long run shows life.
func reportOSStats(ctx context.Context, m *merger, w *Writer, done <-chan struct{}) {
	t := time.NewTicker(consts.LogUpdateInterval)
	defer t.Stop()
	var lastEmitted uint64
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
			log.Printf("os: emitted=%d (+%d/s) dropped=%d merger_in=%d written=%d elapsed=%s",
				cur, delta, dropped, received, w.Written(), elapsed)
		}
	}
}

// reservedHelper is unused; kept here to make the diff cleaner if we later
// add a "warmup" phase that pre-resolves DNS for SMTP HELO etc.
var _ = atomic.Bool{}
