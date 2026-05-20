//go:build !windows

package routes

import "fmt"

type DefaultRoute struct {
	NextHop        string
	InterfaceAlias string
	InterfaceIndex int
}

func DefaultIPv4Route() (DefaultRoute, error) {
	return DefaultRoute{}, fmt.Errorf("windows-only client")
}
func InterfaceIndex(alias string) (int, error) { return 0, fmt.Errorf("windows-only client") }
func ConfigureAdapter(alias, clientIP string, mtu int, dns []string, blockIPv6 bool) error {
	return fmt.Errorf("windows-only client")
}
func AddServerBypass(serverIP string, dr DefaultRoute) error {
	return fmt.Errorf("windows-only client")
}
func ConfigureTrafficRoutes(mode string, tunIfIndex int, serverTunIP string, include, exclude []string, dr DefaultRoute) error {
	return fmt.Errorf("windows-only client")
}
func CleanupTrafficRoutes(mode string, tunIfIndex int, serverIP string, include, exclude []string, dr DefaultRoute) {
}
func CleanupAdapter(alias string, resetIPv6 bool) {}
func AdapterStatus(alias string) (string, error)  { return "", fmt.Errorf("windows-only client") }
func Doctor(alias string) (string, error)         { return "", fmt.Errorf("windows-only client") }
