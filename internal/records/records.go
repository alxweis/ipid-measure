package records

type ZMap struct {
	IPAddress string `parquet:"IP_ADDR,plain"`
	ReplyType string `parquet:"REPLY_TYPE"`
}

type OSRecord struct {
	IPAddress        string `parquet:"IP_ADDR"`
	TimestampUS      int64  `parquet:"TIMESTAMP_US"`
	OSName           string `parquet:"OS_NAME"`
	OSSource         string `parquet:"OS_SOURCE"`
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
