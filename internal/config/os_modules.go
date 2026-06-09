package config

import "errors"

type OSModules struct {
	SSH   bool `yaml:"ssh"`
	SMB   bool `yaml:"smb"`
	HTTP  bool `yaml:"http"`
	HTTPS bool `yaml:"https"`
	SNMP  bool `yaml:"snmp"`
	SMTP  bool `yaml:"smtp"`

	MSSQL    bool `yaml:"mssql"`
	POP3     bool `yaml:"pop3"`
	IMAP     bool `yaml:"imap"`
	FTP      bool `yaml:"ftp"`
	TELNET   bool `yaml:"telnet"`
	DNSChaos bool `yaml:"dns_chaos"`
}

func HasZGrab2Module(modules OSModules) bool {
	return modules.SSH ||
		modules.SMB ||
		modules.HTTP ||
		modules.HTTPS ||
		modules.SMTP ||
		modules.MSSQL ||
		modules.POP3 ||
		modules.IMAP ||
		modules.FTP ||
		modules.TELNET
}

func HasZDNSModule(modules OSModules) bool {
	return modules.DNSChaos
}

func HasSNMPModule(modules OSModules) bool {
	return modules.SNMP
}

func HasModule(modules OSModules) bool {
	return modules.SSH ||
		modules.SMB ||
		modules.HTTP ||
		modules.HTTPS ||
		modules.SNMP ||
		modules.SMTP ||
		modules.MSSQL ||
		modules.POP3 ||
		modules.IMAP ||
		modules.FTP ||
		modules.TELNET ||
		modules.DNSChaos
}

func validateOSModules(modules OSModules) error {
	if !HasModule(modules) {
		return errors.New("no os modules selected")
	}
	return nil
}
