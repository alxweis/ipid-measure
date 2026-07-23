package records

type ZMap struct {
	IPAddress string `parquet:"IP_ADDR,plain"`
	ReplyType string `parquet:"REPLY_TYPE"`
}

type OSRecord struct {
	IPAddress        string `parquet:"IP_ADDR,plain"`
	OSName           string `parquet:"OS_NAME"`
	DetectedName     string `parquet:"DETECTED_NAME"`
	DetectedType     string `parquet:"DETECTED_TYPE"`
	OSSource         string `parquet:"OS_SOURCE"`
	SSHServerID      string `parquet:"SSH_SERVER_ID,plain"`
	SMBNativeOS      string `parquet:"SMB_NATIVE_OS,plain"`
	HTTPServer       string `parquet:"HTTP_SERVER,plain"`
	HTTPSServer      string `parquet:"HTTPS_SERVER,plain"`
	HTTPSCertIssuer  string `parquet:"HTTPS_CERT_ISSUER,plain"`
	HTTPSCertSubject string `parquet:"HTTPS_CERT_SUBJECT,plain"`
	SNMPSysDescr     string `parquet:"SNMP_SYS_DESCR,plain"`
	SMTPBanner       string `parquet:"SMTP_BANNER,plain"`
	SMTPEHLO         string `parquet:"SMTP_EHLO_RESPONSE,plain"`
	MSSQLVersion     string `parquet:"MSSQL_VERSION,plain"`
	POP3Banner       string `parquet:"POP3_BANNER,plain"`
	IMAPBanner       string `parquet:"IMAP_BANNER,plain"`
	FTPBanner        string `parquet:"FTP_BANNER,plain"`
	TelnetBanner     string `parquet:"TELNET_BANNER,plain"`
	DNSVersionBind   string `parquet:"DNS_VERSION_BIND,plain"`
	DNSHostnameBind  string `parquet:"DNS_HOSTNAME_BIND,plain"`
}

type IPIDRecord struct {
	IPAddress                string `parquet:"IP_ADDR,plain"`
	IPIDSequence             string `parquet:"IPID_SEQUENCE,plain"`
	SendTimestampSequence    string `parquet:"SEND_TIMESTAMP_SEQUENCE,plain"`
	ReceiveTimestampSequence string `parquet:"RECEIVE_TIMESTAMP_SEQUENCE,plain"`
}
