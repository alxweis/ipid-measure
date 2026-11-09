package os

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/parquet-go/parquet-go"
)

func BenchmarkResumeMillionTargets(b *testing.B) {
	c, old, _, _ := resumeFixture(b)
	f, err := os.Create(c.TargetFile)
	if err != nil {
		b.Fatal(err)
	}
	w := parquet.NewGenericWriter[records.ZMap](f)
	of, err := os.Create(filepath.Join(old, "os-observations.pq"))
	if err != nil {
		b.Fatal(err)
	}
	ow := parquet.NewGenericWriter[observation](of)
	batch := make([]records.ZMap, 10000)
	observed := make([]observation, 10000)
	for block := 0; block < 100; block++ {
		for i := range batch {
			n := uint32(block*10000+i) + (1 << 24)
			ip := fmt.Sprintf("%d.%d.%d.%d", n>>24, (n>>16)&255, (n>>8)&255, n&255)
			batch[i] = records.ZMap{IPAddress: ip}
			observed[i] = observation{IP: ip, Status: "no-evidence"}
		}
		if _, err := w.Write(batch); err != nil {
			b.Fatal(err)
		}
		if block < 50 {
			if _, err := ow.Write(observed); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	f.Close()
	if err := ow.Close(); err != nil {
		b.Fatal(err)
	}
	of.Close()
	if err := parquet.WriteFile[records.OSRecord](filepath.Join(old, "os.pq"), nil); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dir := b.TempDir()
		out := filepath.Join(dir, "os.pq")
		writer, err := NewWriter(out)
		if err != nil {
			b.Fatal(err)
		}
		_, cancel := context.WithCancel(context.Background())
		obs, err := newObservationWriter(filepath.Join(dir, "os-observations.pq"), cancel)
		if err != nil {
			b.Fatal(err)
		}
		state, err := restoreOS(context.Background(), c, out, writer, obs, newCoverageStats(1000000), 1000000)
		if err != nil {
			b.Fatal(err)
		}
		if state.completed.count != 500000 {
			b.Fatal(state.completed.count)
		}
		writer.Close()
		obs.close(obs.count)
		cancel()
	}
	b.ReportMetric(float64(1000000*b.N)/b.Elapsed().Seconds(), "input-IPs/s")
}

func BenchmarkDNSChaosTimeoutConcurrency(b *testing.B) {
	for _, workers := range []int{100, 1000} {
		b.Run(fmt.Sprint(workers), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				in := make(chan string, 5000)
				for n := 0; n < 5000; n++ {
					in <- "127.0.0.254"
				}
				close(in)
				count := 0
				for range NewDNSChaosProbe(5*time.Millisecond).Run(context.Background(), in, workers) {
					count++
				}
				if count != 5000 {
					b.Fatal(count)
				}
			}
			b.ReportMetric(float64(5000*b.N)/b.Elapsed().Seconds(), "completions/s")
		})
	}
}
