//go:build windows

package routes

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"sshtun_pool_client/internal/ipcalc"
)

type DefaultRoute struct {
	NextHop        string
	InterfaceAlias string
	InterfaceIndex int
}

func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("powershell failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func DefaultIPv4Route() (DefaultRoute, error) {
	script := `$rt = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; if (-not $rt) { throw 'default route not found' }; Write-Output "$($rt.NextHop)|$($rt.InterfaceAlias)|$($rt.ifIndex)"`
	out, err := runPowerShell(script)
	if err != nil {
		return DefaultRoute{}, err
	}
	parts := strings.Split(out, "|")
	if len(parts) != 3 {
		return DefaultRoute{}, fmt.Errorf("unexpected default route output: %q", out)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(parts[2]))
	if err != nil {
		return DefaultRoute{}, err
	}
	return DefaultRoute{NextHop: strings.TrimSpace(parts[0]), InterfaceAlias: strings.TrimSpace(parts[1]), InterfaceIndex: idx}, nil
}

func InterfaceIndex(alias string) (int, error) {
	script := fmt.Sprintf(`$a = Get-NetAdapter -Name %q -ErrorAction Stop; Write-Output $a.ifIndex`, alias)
	out, err := runPowerShell(script)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

func ConfigureAdapter(alias, clientIP string, mtu int, dns []string, blockIPv6 bool) error {
	dnsLiteral := "@()"
	if len(dns) > 0 {
		quoted := make([]string, 0, len(dns))
		for _, d := range dns {
			quoted = append(quoted, fmt.Sprintf("'%s'", strings.ReplaceAll(d, "'", "''")))
		}
		dnsLiteral = "@(" + strings.Join(quoted, ",") + ")"
	}
	script := fmt.Sprintf(`
$alias = %q
$ip = %q
$mtu = %d
$dns = %s
$blockIPv6 = %s
$adapter = Get-NetAdapter -Name $alias -ErrorAction Stop
if ($blockIPv6) { Disable-NetAdapterBinding -Name $alias -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue }
Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $ip -PrefixLength 30 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
netsh interface ipv4 set subinterface name="$alias" mtu=$mtu store=active | Out-Null
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -InterfaceMetric 1 -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue
if ($dns.Count -gt 0) { Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dns -ErrorAction SilentlyContinue }
`, alias, clientIP, mtu, dnsLiteral, boolPSS(blockIPv6))
	_, err := runPowerShell(script)
	return err
}

func AddServerBypass(serverIP string, dr DefaultRoute) error {
	if net.ParseIP(serverIP) == nil {
		return fmt.Errorf("bad server IP: %s", serverIP)
	}
	prefix := serverIP + "/32"
	return replaceRoute(prefix, dr.InterfaceIndex, dr.NextHop, 1)
}

func ConfigureTrafficRoutes(mode string, tunIfIndex int, serverTunIP string, include, exclude []string, dr DefaultRoute, routeStyle string) error {
	mode = strings.ToLower(mode)
	// Match the previously working Windows implementation: add routes via the
	// server-side tunnel IP. The adapter has a /30 address, so serverTunIP is
	// directly reachable on the Wintun interface. --route-style onlink remains
	// available for diagnostics.
	tunNextHop := serverTunIP
	if strings.EqualFold(routeStyle, "onlink") {
		tunNextHop = "0.0.0.0"
	}
	if mode == "full" {
		if err := replaceRoute("0.0.0.0/1", tunIfIndex, tunNextHop, 1); err != nil {
			return err
		}
		if err := replaceRoute("128.0.0.0/1", tunIfIndex, tunNextHop, 1); err != nil {
			return err
		}
	} else {
		for _, cidr := range include {
			if err := replaceRoute(cidr, tunIfIndex, tunNextHop, 1); err != nil {
				return err
			}
		}
	}
	for _, cidr := range exclude {
		if err := replaceRoute(cidr, dr.InterfaceIndex, dr.NextHop, 1); err != nil {
			return err
		}
	}
	return nil
}

func CleanupTrafficRoutes(mode string, tunIfIndex int, serverIP string, include, exclude []string, dr DefaultRoute) {
	mode = strings.ToLower(mode)
	if mode == "full" {
		deleteRoute("0.0.0.0/1", tunIfIndex)
		deleteRoute("128.0.0.0/1", tunIfIndex)
	} else {
		for _, cidr := range include {
			deleteRoute(cidr, tunIfIndex)
		}
	}
	for _, cidr := range exclude {
		deleteRoute(cidr, dr.InterfaceIndex)
	}
	if serverIP != "" {
		deleteRoute(serverIP+"/32", dr.InterfaceIndex)
	}
}

func CleanupAdapter(alias string, resetIPv6 bool) {
	script := fmt.Sprintf(`
$alias = %q
$a = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
if ($a) {
  Get-NetRoute -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -ne '0.0.0.0/0'} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
  if ($resetIPv6) { Enable-NetAdapterBinding -Name $alias -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue }
}
`, alias)
	_, _ = runPowerShell(script)
}

func boolPSS(v bool) string {
	if v {
		return "$true"
	}
	return "$false"
}

func AdapterStatus(alias string) (string, error) {
	script := fmt.Sprintf(`
$alias = %q
$a = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
if (-not $a) { Write-Output "adapter not found: $alias"; exit 0 }
Write-Output "Adapter: $($a.Name) status=$($a.Status) ifIndex=$($a.ifIndex) mac=$($a.MacAddress)"
Write-Output "IPv4:"
Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-Table IPAddress,PrefixLength,AddressState,SkipAsSource -AutoSize | Out-String | Write-Output
Write-Output "Routes:"
Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object DestinationPrefix | Format-Table DestinationPrefix,NextHop,RouteMetric -AutoSize | Out-String | Write-Output
Write-Output "DNS:"
Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-List | Out-String | Write-Output
`, alias)
	return runPowerShell(script)
}

func Doctor(alias string) (string, error) {
	script := fmt.Sprintf(`
Write-Output "Default IPv4 routes:"
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Format-Table DestinationPrefix,NextHop,InterfaceAlias,ifIndex,RouteMetric,InterfaceMetric -AutoSize | Out-String | Write-Output
Write-Output ""
$alias = %q
$a = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
if ($a) {
  Write-Output "Adapter: $($a.Name) status=$($a.Status) ifIndex=$($a.ifIndex)"
  Write-Output "IPv4 addresses:"
  Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-Table IPAddress,PrefixLength,AddressState,SkipAsSource -AutoSize | Out-String | Write-Output
  Write-Output "Adapter routes:"
  Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object DestinationPrefix | Format-Table DestinationPrefix,NextHop,RouteMetric -AutoSize | Out-String | Write-Output
  Write-Output "Adapter MTU:"
  netsh interface ipv4 show subinterfaces | Select-String -SimpleMatch $alias | Out-String | Write-Output
} else {
  Write-Output "Adapter not found: $alias"
}
`, alias)
	return runPowerShell(script)
}

func replaceRoute(prefix string, ifIndex int, nextHop string, metric int) error {
	if _, _, _, err := ipcalc.CIDRToMaskAndNetwork(prefix); err != nil {
		return err
	}
	script := fmt.Sprintf(`
$prefix = %q
$ifIndex = %d
$nextHop = %q
$metric = %d
Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -NextHop $nextHop -RouteMetric $metric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
`, prefix, ifIndex, nextHop, metric)
	_, err := runPowerShell(script)
	return err
}

func deleteRoute(prefix string, ifIndex int) {
	script := fmt.Sprintf(`Get-NetRoute -DestinationPrefix %q -InterfaceIndex %d -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`, prefix, ifIndex)
	_, _ = runPowerShell(script)
}
