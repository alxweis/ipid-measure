package records

type ZMap struct {
	IPAddress string `parquet:"IP_ADDR,plain"`
	ReplyType string `parquet:"REPLY_TYPE"`
}

type OSRecord struct {
	IPAddress string  `parquet:"IP_ADDR,plain"`
	OSStatus  string  `parquet:"OS_STATUS,dict"`
	OSTag     *string `parquet:"OS_TAG,optional,dict"`

	SSHOS   *string `parquet:"SSH_OS_TAG,optional,dict"`
	SMBOS   *string `parquet:"SMB_OS_TAG,optional,dict"`
	HTTPOS  *string `parquet:"HTTP_OS_TAG,optional,dict"`
	HTTPSOS *string `parquet:"HTTPS_OS_TAG,optional,dict"`
	SNMPOS  *string `parquet:"SNMP_OS_TAG,optional,dict"`
	DNSOS   *string `parquet:"DNS_OS_TAG,optional,dict"`

	SSHServerID    *string `parquet:"SSH_SERVER_ID,optional"`
	SMBNativeOS    *string `parquet:"SMB_NATIVE_OS,optional"`
	HTTPServer     *string `parquet:"HTTP_SERVER,optional"`
	HTTPSServer    *string `parquet:"HTTPS_SERVER,optional"`
	SNMPSysDescr   *string `parquet:"SNMP_SYS_DESCR,optional"`
	DNSVersionBind *string `parquet:"DNS_VERSION_BIND,optional"`
}

type IPIDRecord struct {
	IPAddress                string `parquet:"IP_ADDR,plain"`
	IPIDSequence             string `parquet:"IPID_SEQUENCE,plain"`
	SendTimestampSequence    string `parquet:"SEND_TIMESTAMP_SEQUENCE,plain"`
	ReceiveTimestampSequence string `parquet:"RECEIVE_TIMESTAMP_SEQUENCE,plain"`
}
