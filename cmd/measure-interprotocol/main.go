package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/logger"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/internal/upload"
	"github.com/alxweis/ipid-measure/ipid/measurement"

	_ "github.com/alxweis/ipid-measure/ipid/receiver"
	_ "github.com/alxweis/ipid-measure/ipid/stats"
	_ "github.com/alxweis/ipid-measure/ipid/worker"
	"gopkg.in/yaml.v3"
)

const goMemLimitDefaultBytes = 700 << 20

type interProtocolSnapshot struct {
	config.IPIDConfig `yaml:",inline"`
	InterProtocol     struct {
		Protocols []string `yaml:"protocols"`
		TCPPort   uint16   `yaml:"tcp_port"`
		UDPPort   uint16   `yaml:"udp_port"`
		Schedule  string   `yaml:"schedule"`
		Retries   int      `yaml:"retries"`
	} `yaml:"interprotocol"`
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	configFlag := flag.String("config", files.IPIDConfigFilePath, "base IPID config (interfaces, limits, TCP flags)")
	targetFlag := flag.String("target-file", "", "same-strategy inter-protocol target parquet")
	protocolFlag := flag.String("protocols", "icmp,tcp,udp", "icmp,tcp | icmp,udp | tcp,udp | icmp,tcp,udp")
	tcpPort := flag.Uint("tcp-port", 80, "stateless TCP destination port")
	udpPort := flag.Uint("udp-port", 53, "UDP DNS destination port")
	printID := flag.Bool("print-id", false, "print measurement id on success")
	flag.Parse()
	if *targetFlag == "" {
		log.Fatal("--target-file is required")
	}
	protocols, names, err := parseProtocols(*protocolFlag)
	if err != nil {
		log.Fatal(err)
	}
	if *tcpPort > 65535 || *udpPort > 65535 {
		log.Fatal("ports must be in [0,65535]")
	}
	configPath, err := filepath.Abs(*configFlag)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}
	c, err := config.LoadIPIDConfig(configPath, func(c *config.IPIDConfig) {
		// Inter-protocol targets are explicit Parquet files, so the unrelated
		// single-protocol ZMap reference in the shared config must not gate a run.
		switch protocols[0] {
		case types.PayloadTCP:
			c.ZMapID = fmt.Sprintf("tcp-%d_1970-01-01_00-00-00", *tcpPort)
		case types.PayloadUDPDNS:
			c.ZMapID = fmt.Sprintf("udp-dns-%d_1970-01-01_00-00-00", *udpPort)
		default:
			c.ZMapID = "icmp_1970-01-01_00-00-00"
		}
		c.TargetFile = *targetFlag
		c.MeasurementMode = types.MeasurementModeRTBased
		c.TCPConfig.EstablishConnection = false
		c.AnalysisWorkflowConfig.Enable = false
	})
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	measurement.InterProtocols = protocols
	measurement.InterProtocolPorts = map[types.Payload]uint16{
		types.PayloadTCP: uint16(*tcpPort), types.PayloadUDPDNS: uint16(*udpPort),
	}
	debug.SetMemoryLimit(config.GoMemoryLimitOrDefault(c.GoMemoryLimit, goMemLimitDefaultBytes))
	m := paths.NewInterProtocolMeasurement(protocols, time.Now())
	if err := m.CreateDirectory(); err != nil {
		log.Fatalf("create measurement directory: %v", err)
	}
	if err := m.CreateZMapLink(c.ZMapFilePath); err != nil {
		log.Fatalf("create target symlink: %v", err)
	}
	snapshot := interProtocolSnapshot{IPIDConfig: *c}
	snapshot.InterProtocol.Protocols = names
	snapshot.InterProtocol.TCPPort = uint16(*tcpPort)
	snapshot.InterProtocol.UDPPort = uint16(*udpPort)
	snapshot.InterProtocol.Schedule = "rt-based, protocol order repeated per logical connection/request"
	snapshot.InterProtocol.Retries = 0
	data, err := yaml.Marshal(snapshot)
	if err != nil {
		log.Fatalf("marshal snapshot: %v", err)
	}
	if err := writeSnapshot(m.ConfigSnapshotPath, data); err != nil {
		log.Fatalf("write snapshot: %v", err)
	}
	if c.LogToFile {
		closer, err := logger.SetupFile(m.LogFilePath)
		if err != nil {
			log.Fatalf("setup log: %v", err)
		}
		defer closer()
	}
	records, err := measurement.Run(c, m)
	if err != nil {
		log.Fatalf("run inter-protocol measurement (wrote %d rows): %v", records, err)
	}
	log.Printf("inter-protocol measurement completed: %s (records=%d)", m.Path, records)
	if err := upload.Upload(c.UploadConfig, m.Measurement); err != nil {
		log.Fatalf("upload measurement: %v", err)
	}
	if *printID {
		fmt.Println(m.ID)
	}
}

func writeSnapshot(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func parseProtocols(value string) ([]types.Payload, []string, error) {
	names := strings.Split(strings.ToLower(strings.TrimSpace(value)), ",")
	valid := map[string]types.Payload{"icmp": types.PayloadICMP, "tcp": types.PayloadTCP, "udp": types.PayloadUDPDNS}
	protocols := make([]types.Payload, len(names))
	for index, name := range names {
		name = strings.TrimSpace(name)
		payload, ok := valid[name]
		if !ok {
			return nil, nil, fmt.Errorf("invalid protocol %q", name)
		}
		names[index], protocols[index] = name, payload
	}
	allowed := map[string]bool{
		"icmp,tcp": true, "icmp,udp": true, "tcp,udp": true, "icmp,tcp,udp": true,
	}
	if !allowed[strings.Join(names, ",")] {
		return nil, nil, fmt.Errorf("unsupported protocol group %q", value)
	}
	return protocols, names, nil
}
