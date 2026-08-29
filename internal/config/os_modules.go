package config

import "errors"

type OSModules struct {
	SSH      bool `yaml:"ssh"`
	SMB      bool `yaml:"smb"`
	HTTP     bool `yaml:"http"`
	HTTPS    bool `yaml:"https"`
	SNMP     bool `yaml:"snmp"`
	DNSChaos bool `yaml:"dns_chaos"`
}

func HasZGrab2Module(modules OSModules) bool {
	return modules.SSH || modules.SMB || modules.HTTP || modules.HTTPS
}

func HasDNSChaosModule(modules OSModules) bool {
	return modules.DNSChaos
}

func HasSNMPModule(modules OSModules) bool {
	return modules.SNMP
}

func HasModule(modules OSModules) bool {
	return HasZGrab2Module(modules) || modules.SNMP || modules.DNSChaos
}

func validateOSModules(modules OSModules) error {
	if !(modules.SSH && modules.SMB && modules.HTTP && modules.HTTPS && modules.SNMP && modules.DNSChaos) {
		return errors.New("ssh, smb, http, https, snmp, and dns_chaos must all be enabled")
	}
	return nil
}
