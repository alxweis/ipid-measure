package zmap

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/records"
)

// ParsedRow is one ZMap result row.
type ParsedRow struct {
	IPAddress string
	ReplyType string // zmap "classification"; for TCP synack/rst, empty if absent
}

// Parser consumes ZMap's CSV stdout incrementally and emits ParsedRow values.
type Parser struct {
	r            *bufio.Reader
	colIP        int // column index of "saddr"
	colReplyType int // column index of "classification" (-1 if not present)
	headerSeen   bool
}

// NewParser constructs a parser from an io.Reader (typically ZMap's stdout).
func NewParser(r io.Reader) *Parser {
	return &Parser{
		r:            bufio.NewReaderSize(r, consts.ZMapStdoutReadBufferBytes),
		colIP:        -1,
		colReplyType: -1,
	}
}

// readHeader reads the first CSV line and locates the columns we care about.
func (p *Parser) readHeader() error {
	line, err := p.readLine()
	if err != nil {
		return err
	}
	for i, c := range strings.Split(line, ",") {
		switch strings.TrimSpace(c) {
		case "saddr":
			p.colIP = i
		case "classification":
			p.colReplyType = i
		}
	}
	if p.colIP < 0 {
		return fmt.Errorf("zmap parser: required column 'saddr' missing from header %q", line)
	}
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
		if row, ok := p.parseRow(line); ok {
			return row, nil
		}
		// Malformed row: skip and keep going.
	}
}

// parseRow extracts the row fields from one CSV line.
func (p *Parser) parseRow(line string) (ParsedRow, bool) {
	var (
		ip        string
		replyType string
		col       int
		start     int
	)
	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ',' {
			field := line[start:i]
			switch col {
			case p.colIP:
				ip = field
			case p.colReplyType:
				replyType = field
			}
			col++
			start = i + 1
		}
	}

	if ip == "" {
		return ParsedRow{}, false
	}
	return ParsedRow{IPAddress: ip, ReplyType: replyType}, true
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
		IPAddress: row.IPAddress,
		ReplyType: row.ReplyType,
	}
}
