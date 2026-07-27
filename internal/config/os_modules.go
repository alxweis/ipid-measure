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
	return HasCoreZGrab2Module(modules) || HasSecondaryZGrab2Module(modules)
}

// HasCoreZGrab2Module reports whether at least one high-yield application
// fingerprint is enabled. These modules run for every target.
func HasCoreZGrab2Module(modules OSModules) bool {
	return modules.SSH ||
		modules.SMB ||
		modules.HTTP ||
		modules.HTTPS
}

// HasSecondaryZGrab2Module reports whether at least one lower-yield banner
// module is enabled. These modules are sampled by the OS pipeline.
func HasSecondaryZGrab2Module(modules OSModules) bool {
	return modules.SMTP ||
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

func HasCoreModule(modules OSModules) bool {
	return HasCoreZGrab2Module(modules) || HasSNMPModule(modules)
}

func HasSecondaryModule(modules OSModules) bool {
	return HasSecondaryZGrab2Module(modules) || HasZDNSModule(modules)
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
