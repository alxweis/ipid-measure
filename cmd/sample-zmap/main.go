package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/alxweis/ipid-measure/internal/dirs"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/root"
	"github.com/alxweis/ipid-measure/internal/zmapsample"
)

const metadataVersion = 1

type metadata struct {
	Version     int       `json:"version"`
	ZMapID      string    `json:"zmap_id"`
	SourceRows  int64     `json:"source_rows"`
	SampleRows  int64     `json:"sample_rows"`
	MinimumRows int64     `json:"minimum_rows"`
	Percent     int       `json:"percent"`
	Seed        int64     `json:"seed"`
	CreatedAt   time.Time `json:"created_at"`
}

func main() {
	zmapID := flag.String("zmap", "", "source ZMap measurement id")
	minimum := flag.Int64("minimum", 1_000_000, "minimum sample rows (capped at source size)")
	percent := flag.Int("percent", 10, "sample percentage")
	seed := flag.Int64("seed", 0, "PRNG seed; 0 generates a cryptographically random seed")
	flag.Parse()

	if *zmapID == "" {
		log.Fatal("--zmap is required")
	}
	if _, _, _, err := paths.ParseMeasurementID(*zmapID); err != nil {
		log.Fatalf("invalid --zmap: %v", err)
	}
	if *minimum < 1 {
		log.Fatal("--minimum must be at least 1")
	}
	if *percent < 1 || *percent > 100 {
		log.Fatal("--percent must be in [1,100]")
	}

	directory := filepath.Join(root.Root, dirs.ZMapDir, dirs.RawDir, *zmapID)
	inputPath := filepath.Join(directory, files.ZMapMeasurementFile)
	outputPath := filepath.Join(directory, files.ZMapFixedBaseSampleFile)
	metadataPath := filepath.Join(directory, files.ZMapFixedBaseSampleMetadataFile)

	if fileExists(outputPath) || fileExists(metadataPath) {
		if err := validateExisting(inputPath, outputPath, metadataPath, *zmapID, *minimum, *percent); err != nil {
			log.Fatalf("reuse existing sample: %v", err)
		}
		log.Printf("reusing fixed-base target sample: %s", outputPath)
		fmt.Println(outputPath)
		return
	}

	actualSeed := *seed
	if actualSeed == 0 {
		var bytes [8]byte
		if _, err := cryptorand.Read(bytes[:]); err != nil {
			log.Fatalf("generate random seed: %v", err)
		}
		actualSeed = int64(binary.LittleEndian.Uint64(bytes[:]))
	}

	stats, err := zmapsample.WriteUniformSample(
		inputPath, outputPath, *minimum, *percent, actualSeed,
	)
	if err != nil {
		log.Fatalf("create fixed-base target sample: %v", err)
	}
	value := metadata{
		Version:     metadataVersion,
		ZMapID:      *zmapID,
		SourceRows:  stats.SourceRows,
		SampleRows:  stats.SampleRows,
		MinimumRows: *minimum,
		Percent:     *percent,
		Seed:        stats.Seed,
		CreatedAt:   time.Now().UTC(),
	}
	if err := writeMetadata(metadataPath, value); err != nil {
		_ = os.Remove(outputPath)
		log.Fatalf("write sample metadata: %v", err)
	}

	log.Printf(
		"fixed-base target sample completed: rows=%d/%d seed=%d path=%s",
		stats.SampleRows, stats.SourceRows, stats.Seed, outputPath,
	)
	fmt.Println(outputPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func parquetRows(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader := parquet.NewGenericReader[records.ZMap](file)
	defer reader.Close()
	return reader.NumRows(), nil
}

func validateExisting(inputPath, outputPath, metadataPath, zmapID string, minimum int64, percent int) error {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("read metadata: %w", err)
	}
	var value metadata
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode metadata: %w", err)
	}
	if value.Version != metadataVersion || value.ZMapID != zmapID ||
		value.MinimumRows != minimum || value.Percent != percent {
		return fmt.Errorf("metadata does not match the requested sample")
	}
	sourceRows, err := parquetRows(inputPath)
	if err != nil {
		return fmt.Errorf("inspect source parquet: %w", err)
	}
	sampleRows, err := parquetRows(outputPath)
	if err != nil {
		return fmt.Errorf("inspect sample parquet: %w", err)
	}
	wanted := zmapsample.FixedBaseSampleSize(sourceRows, minimum, percent)
	if value.SourceRows != sourceRows || value.SampleRows != wanted || sampleRows != wanted {
		return fmt.Errorf(
			"row counts do not match: source=%d metadata_source=%d sample=%d metadata_sample=%d wanted=%d",
			sourceRows, value.SourceRows, sampleRows, value.SampleRows, wanted,
		)
	}
	return nil
}

func writeMetadata(path string, value metadata) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary := path + ".part"
	if err := os.WriteFile(temporary, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}
