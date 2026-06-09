package config

import (
	"fmt"
	"net"
)

type Interface struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
}

type InterfacePair struct {
	A Interface `yaml:"a"`
	B Interface `yaml:"b"`
}

func validateInterface(
	iface Interface,
	path string,
	requireSend bool,
	requireReceive bool,
) error {
	if iface.Name == "" {
		return fmt.Errorf("%s.name must not be empty", path)
	}

	if iface.IP == "" {
		return fmt.Errorf("%s.ip must not be empty", path)
	}

	parsedIP := net.ParseIP(iface.IP)
	if parsedIP == nil {
		return fmt.Errorf("%s.ip is not a valid IP address", path)
	}

	// ==================================================
	// Check interface existence
	// ==================================================

	netInterface, err := net.InterfaceByName(iface.Name)
	if err != nil {
		return fmt.Errorf(
			"%s.name interface does not exist: %w",
			path,
			err,
		)
	}

	if netInterface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("%s.name interface is down", path)
	}

	// ==================================================
	// Check assigned IP
	// ==================================================

	addrs, err := netInterface.Addrs()
	if err != nil {
		return fmt.Errorf(
			"get addresses for %s.name: %w",
			path,
			err,
		)
	}

	foundIP := false

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ipNet.IP.Equal(parsedIP) {
			foundIP = true
			break
		}
	}

	if !foundIP {
		return fmt.Errorf(
			"%s.ip is not assigned to interface %s",
			path,
			iface.Name,
		)
	}

	// ==================================================
	// Permission checks
	// ==================================================

	if requireSend {
		conn, err := net.ListenPacket(
			"ip4:icmp",
			parsedIP.String(),
		)
		if err != nil {
			return fmt.Errorf(
				"%s send access check failed: %w",
				path,
				err,
			)
		}

		if err := conn.Close(); err != nil {
			return fmt.Errorf(
				"%s close send socket: %w",
				path,
				err,
			)
		}
	}

	if requireReceive {
		conn, err := net.ListenPacket(
			"ip4:icmp",
			parsedIP.String(),
		)
		if err != nil {
			return fmt.Errorf(
				"%s receive access check failed: %w",
				path,
				err,
			)
		}

		if err := conn.Close(); err != nil {
			return fmt.Errorf(
				"%s close receive socket: %w",
				path,
				err,
			)
		}
	}

	return nil
}
