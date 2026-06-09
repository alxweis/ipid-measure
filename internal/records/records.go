package records

// ZMap is one responsive target found by a ZMap scan together with the
// microsecond timestamp at which the response was observed. The IPID measurement
// reads the IPAddress column to know whom to probe; the timestamp is preserved
// so consumers can correlate or window the input scan if they want to.
//
// Adding a column here is backward-compatible: old parquet files that only have
// IP_ADDR are still read correctly (TIMESTAMP_US defaults to 0).
type ZMap struct {
	IPAddress   string `parquet:"IP_ADDR"`
	TimestampUS int64  `parquet:"TIMESTAMP_US"`
}

// OSRecord is one resolved OS-fingerprint row. The IPID measurement does not
// consume this file; it is a deliverable in its own right (downstream
// dashboards / IPv4-OS distribution analytics).
//
// Only fields where OS-related information can theoretically appear are
// modelled as separate columns. A row is only written when at least one
// fingerprint source produced a non-empty OS_NAME; for stub/empty rows we
// skip the write entirely so os.pq is dense in useful data.
//
// All string fields default to "" when the corresponding service did not
// respond or did not yield OS-relevant data.
type OSRecord struct {
	IPAddress   string `parquet:"IP_ADDR"`
	TimestampUS int64  `parquet:"TIMESTAMP_US"`

	// OSName is the normalised OS family (see os/fingerprint.go). Lowercase,
	// no version, e.g. "ubuntu", "windows", "freebsd", "cisco-ios", "linux".
	OSName string `parquet:"OS_NAME"`

	// OSSource identifies which probe field produced the OS_NAME match, so
	// downstream analytics can attribute coverage to data sources.
	// Examples: "ssh", "smb-native-os", "snmp-sysdescr", "dns-chaos".
	OSSource string `parquet:"OS_SOURCE"`

	// Raw (or lightly normalised) per-service strings. Only fields where OS
	// info can theoretically appear are kept. Each is empty when no useful
	// data was captured.
	SSHServerID      string `parquet:"SSH_SERVER_ID"`
	SMBNativeOS      string `parquet:"SMB_NATIVE_OS"`
	HTTPServer       string `parquet:"HTTP_SERVER"`
	HTTPSServer      string `parquet:"HTTPS_SERVER"`
	HTTPSCertIssuer  string `parquet:"HTTPS_CERT_ISSUER"`
	HTTPSCertSubject string `parquet:"HTTPS_CERT_SUBJECT"`
	SNMPSysDescr     string `parquet:"SNMP_SYS_DESCR"`
	SMTPBanner       string `parquet:"SMTP_BANNER"`
	SMTPEHLO         string `parquet:"SMTP_EHLO_RESPONSE"`
	MSSQLVersion     string `parquet:"MSSQL_VERSION"`
	POP3Banner       string `parquet:"POP3_BANNER"`
	IMAPBanner       string `parquet:"IMAP_BANNER"`
	FTPBanner        string `parquet:"FTP_BANNER"`
	TelnetBanner     string `parquet:"TELNET_BANNER"`
	DNSVersionBind   string `parquet:"DNS_VERSION_BIND"`
	DNSHostnameBind  string `parquet:"DNS_HOSTNAME_BIND"`
}

type IPIDRecord struct {
	IPAddress                string `parquet:"IP_ADDR"`
	IPIDSequence             string `parquet:"IPID_SEQUENCE"`
	SendTimestampSequence    string `parquet:"SEND_TIMESTAMP_SEQUENCE"`
	ReceiveTimestampSequence string `parquet:"RECEIVE_TIMESTAMP_SEQUENCE"`
}
