package zmap

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/netd-tud/ipid-measure/internal/consts"
	"github.com/netd-tud/ipid-measure/internal/records"
)

// ParsedRow is one ZMap result row, normalised into the form the writer wants.
type ParsedRow struct {
	IPAddress   string
	TimestampUS int64
}

// Parser consumes ZMap's CSV stdout incrementally and emits ParsedRow values.
type Parser struct {
	r          *bufio.Reader
	colIP      int // column index of "saddr"
	colTsSec   int // column index of "timestamp-ts"
	colTsUsec  int // column index of "timestamp-us"
	headerSeen bool
	numCols    int
}

// NewParser constructs a parser from an io.Reader (typically ZMap's stdout).
func NewParser(r io.Reader) *Parser {
	return &Parser{
		r:         bufio.NewReaderSize(r, consts.ZMapStdoutReadBufferBytes),
		colIP:     -1,
		colTsSec:  -1,
		colTsUsec: -1,
	}
}

// readHeader reads the first CSV line.
func (p *Parser) readHeader() error {
	line, err := p.readLine()
	if err != nil {
		return err
	}
	cols := strings.Split(line, ",")
	for i, c := range cols {
		switch strings.TrimSpace(c) {
		case "saddr":
			p.colIP = i
		case "timestamp-ts":
			p.colTsSec = i
		case "timestamp-us":
			p.colTsUsec = i
		}
	}
	if p.colIP < 0 {
		return fmt.Errorf("zmap parser: required column 'saddr' missing from header %q", line)
	}
	p.numCols = len(cols)
	p.headerSeen = true
	return nil
}

// Next returns the next row.
func (p *Parser) Next() (ParsedRow, error) {
	if !p.headerSeen {
		if err := p.readHeader(); err != nil {
			return ParsedRow{}, err
		}
	}

	for {
		line, err := p.readLine()
		if err != nil {
			return ParsedRow{}, err
		}
		if line == "" {
			continue
		}

		row, ok := p.parseRow(line)
		if !ok {
			// Malformed row: skip and keep going
			continue
		}
		return row, nil
	}
}

// parseRow extracts the row fields from one CSV line.
func (p *Parser) parseRow(line string) (ParsedRow, bool) {
	var (
		ip    string
		tsSec int64
		tsUs  int64
		col   int
		start int
	)
	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ',' {
			field := line[start:i]
			switch col {
			case p.colIP:
				ip = field
			case p.colTsSec:
				if v, err := strconv.ParseInt(field, 10, 64); err == nil {
					tsSec = v
				}
			case p.colTsUsec:
				if v, err := strconv.ParseInt(field, 10, 64); err == nil {
					tsUs = v
				}
			}
			col++
			start = i + 1
		}
	}

	if ip == "" {
		return ParsedRow{}, false
	}

	// Combine seconds + microseconds into a single µs timestamp
	return ParsedRow{
		IPAddress:   ip,
		TimestampUS: tsSec*1_000_000 + tsUs,
	}, true
}

// readLine reads one line, stripping CR/LF.
func (p *Parser) readLine() (string, error) {
	s, err := p.r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '\r' {
		s = s[:len(s)-1]
	}
	if s == "" && err == io.EOF {
		return "", io.EOF
	}
	return s, nil
}

// ToRecord converts a ParsedRow into the parquet schema used by records.ZMap.
func ToRecord(row ParsedRow) records.ZMap {
	return records.ZMap{
		IPAddress:   row.IPAddress,
		TimestampUS: row.TimestampUS,
	}
}
