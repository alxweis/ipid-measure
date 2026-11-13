package worker

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"

	"github.com/parquet-go/parquet-go"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/rtresume"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/probe"
	"github.com/alxweis/ipid-measure/ipid/stats"
)

type target struct {
	ip       net.IP
	strategy string
}

var targets chan target

func StartAll() {
	numberOfInflightProbes := uint64(measurement.Config.NumberOfInflightProbes)
	targets = make(chan target, numberOfInflightProbes*2)

	for i := uint64(0); i < numberOfInflightProbes; i++ {
		measurement.WorkerWg.Add(1)
		go proberLoop()
	}
}

func CloseTargets() {
	close(targets)
}

func proberLoop() {
	defer measurement.WorkerWg.Done()

	packets := make([][]byte, measurement.RequestCount)

	for {
		select {
		case <-measurement.StopSignal:
			return
		case current, ok := <-targets:
			if !ok {
				return
			}
			ok = probe.MeasureTarget(current.ip, current.strategy, packets)
			if !ok && measurement.IsInterProtocol() {
				measurement.Fail(fmt.Errorf("interprotocol measurement failed for %s", current.ip))
			}
		}
	}
}

func StreamZMapToWorkers() error {
	file, err := os.Open(measurement.Paths.ZMapLinkPath)
	if err != nil {
		return fmt.Errorf("open zmap parquet: %w", err)
	}
	defer file.Close()

	if measurement.IsInterProtocol() {
		return streamInterProtocolTargets(file)
	}

	reader := parquet.NewGenericReader[records.ZMap](file)
	defer reader.Close()

	// Record the total target count so the stats logger can compute progress.
	atomic.StoreInt64(&stats.NumberOfTargetIPAddresses, reader.NumRows())
	// PyArrow can emit an empty row group whose page offset is not readable.
	// A valid zero-row cohort is complete without reading any data pages.
	if reader.NumRows() == 0 {
		return nil
	}
	if plan := measurement.ResumePlan; plan != nil {
		if err := rtresume.Stable(plan); err != nil {
			return err
		}
		if reader.NumRows() != plan.Total {
			return fmt.Errorf("resume target footer changed")
		}
		// Admission rejects invalid/duplicate input addresses, so this is an
		// exact physical row position as well as the count of started targets.
		if err := reader.SeekToRow(plan.Started); err != nil {
			return fmt.Errorf("seek admitted RT prefix: %w", err)
		}
	}

	buffer := make([]records.ZMap, consts.ZMapReadBufferSize)

	for {
		// Stop streaming promptly if a shutdown was requested.
		select {
		case <-measurement.StopSignal:
			return nil
		default:
		}

		count, err := reader.Read(buffer)

		for i := 0; i < count; i++ {
			ip4 := parseIPv4Fast(buffer[i].IPAddress)
			if ip4 == nil {
				continue
			}
			select {
			case targets <- target{ip: ip4}:
			case <-measurement.StopSignal:
				return nil
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read parquet: %w", err)
		}
		if count == 0 {
			return nil
		}
	}
}

func streamInterProtocolTargets(file *os.File) error {
	reader := parquet.NewGenericReader[records.InterProtocolTarget](file)
	defer reader.Close()
	atomic.StoreInt64(&stats.NumberOfTargetIPAddresses, 0)
	if reader.NumRows() == 0 {
		return nil
	}
	buffer := make([]records.InterProtocolTarget, consts.ZMapReadBufferSize)
	for {
		count, err := reader.Read(buffer)
		for i := 0; i < count; i++ {
			sample, sampleErr := config.InterprotocolSample(buffer[i].Strategy)
			if sampleErr != nil {
				return sampleErr
			}
			if sample != measurement.InterProtocolSample {
				continue
			}
			atomic.AddInt64(&stats.NumberOfTargetIPAddresses, 1)
			ip4 := parseIPv4Fast(buffer[i].IPAddress)
			if ip4 == nil {
				return fmt.Errorf("invalid interprotocol target IP %q", buffer[i].IPAddress)
			}
			select {
			case targets <- target{ip: ip4, strategy: buffer[i].Strategy}:
			case <-measurement.StopSignal:
				return nil
			}
		}
		if errors.Is(err, io.EOF) || (err == nil && count == 0) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read interprotocol target parquet: %w", err)
		}
	}
}

func parseIPv4Fast(s string) net.IP {
	var ip [4]byte
	octet := 0
	val := 0
	hadDigit := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if !hadDigit || octet >= 3 || val > 255 {
				return nil
			}
			ip[octet] = byte(val)
			octet++
			val = 0
			hadDigit = false
			continue
		}
		if c < '0' || c > '9' {
			return nil
		}
		val = val*10 + int(c-'0')
		if val > 255 {
			return nil
		}
		hadDigit = true
	}
	if octet != 3 || !hadDigit {
		return nil
	}
	ip[3] = byte(val)
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]).To4()
}

func init() {
	measurement.StartWorkers = StartAll
	measurement.CloseTargetChans = CloseTargets
	measurement.StreamTargets = StreamZMapToWorkers
}
