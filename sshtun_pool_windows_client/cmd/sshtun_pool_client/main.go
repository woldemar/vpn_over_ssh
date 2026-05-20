package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"sshtun_pool_client/internal/admin"
	"sshtun_pool_client/internal/ipcalc"
	"sshtun_pool_client/internal/packetpump"
	"sshtun_pool_client/internal/routes"
	"sshtun_pool_client/internal/sshtransport"
	"sshtun_pool_client/internal/wintun"

	"golang.org/x/crypto/ssh"
)

const (
	defaultAdapterName = "SSHTUN Pool"
	appStateDirName    = "sshtun_pool_client"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	*s = append(*s, v)
	return nil
}

type options struct {
	Host                 string
	KeyFile              string
	User                 string
	Port                 int
	FixedTun             int
	TunStart             int
	TunEnd               int
	MTU                  int
	TunNetA              int
	TunNetB              int
	FullTunnel           bool
	SetDNS               bool
	DNS                  []string
	BlockIPv6            bool
	AdapterName          string
	HostKeySHA256        string
	AskPassphrase        bool
	ConnectTimeoutSec    int
	KeepaliveSeconds     int
	KeepaliveMisses      int
	IncludeRoutes        []string
	IncludeFiles         []string
	ExcludeRoutes        []string
	ExcludeFiles         []string
	CleanOrphansOnStop   bool
	RemoteSetupRequested bool
	RouteStyle           string
}

type savedState struct {
	PID           int                 `json:"pid"`
	AdapterName   string              `json:"adapter_name"`
	ServerIP      string              `json:"server_ip"`
	RoutingMode   string              `json:"routing_mode"`
	IncludeRoutes []string            `json:"include_routes"`
	ExcludeRoutes []string            `json:"exclude_routes"`
	TunIfIndex    int                 `json:"tun_if_index"`
	DefaultRoute  routes.DefaultRoute `json:"default_route"`
	TunUnit       int                 `json:"tun_unit"`
	ClientIP      string              `json:"client_ip"`
	ServerTunIP   string              `json:"server_tun_ip"`
	CreatedAt     time.Time           `json:"created_at"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "start", "connect":
		if err := runStart(os.Args[2:]); err != nil {
			log.Fatalf("start failed: %v", err)
		}
	case "run":
		// Internal foreground worker. Users should use "start".
		if err := runWorker(os.Args[2:]); err != nil {
			log.Fatalf("worker failed: %v", err)
		}
	case "stop", "cleanup", "disconnect":
		if err := runStop(os.Args[2:]); err != nil {
			log.Fatalf("stop failed: %v", err)
		}
	case "status":
		if err := runStatus(os.Args[2:]); err != nil {
			log.Fatalf("status failed: %v", err)
		}
	case "doctor":
		if err := runDoctor(os.Args[2:]); err != nil {
			log.Fatalf("doctor failed: %v", err)
		}
	case "help", "-h", "--help", "":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`Usage:
  sshtun_pool_client.exe start --host SERVER_IP_OR_DOMAIN --key C:\path\to\id_ed25519 [options]
  sshtun_pool_client.exe stop
  sshtun_pool_client.exe cleanup
  sshtun_pool_client.exe status
  sshtun_pool_client.exe doctor

Start options, aligned with the Linux client:
  --host HOST              SSH-TUN server IP/domain
  --key FILE               private key file
  --user USER              default: sshvpn
  --port PORT              default: 65523
  --tun N                  fixed tun number, for example 100
  --tun-start N            default: 100
  --tun-end N              default: 200
  --mtu N                  default: 1400
  --no-full-tunnel         only create tunnel, do not route all IPv4 via it
  --route CIDR             add route via tunnel; can be repeated
  --route-file FILE        read tunnel routes from file, one CIDR per line
  --include CIDR           alias for --route
  --include-file FILE      alias for --route-file
  --exclude CIDR           direct/bypass route via original default gateway; can be repeated
  --exclude-file FILE      read direct/bypass routes from file, one CIDR per line
  --route-private          route RFC1918 private ranges via tunnel
  --exclude-private        bypass RFC1918 private ranges directly
  --no-dns                 do not configure DNS on the Wintun adapter
  --dns "1.1.1.1 8.8.8.8" DNS servers for tun interface
  --no-block-ipv6          do not disable IPv6 binding on the Wintun adapter
  --no-clean-orphans       accepted for Linux CLI compatibility
  --ask-passphrase         accepted; encrypted keys are prompted automatically on Windows

Windows-specific optional flags:
  --adapter-name NAME      default: SSHTUN Pool
  --host-key-sha256 FP     pin SSH host key, example: SHA256:...
  --route-style STYLE      Windows route style: gateway or onlink; default: gateway

Examples:
  sshtun_pool_client.exe start --host 1.2.3.4 --key .\id_ed25519
  sshtun_pool_client.exe start --host 1.2.3.4 --key .\id_ed25519 --exclude-private
  sshtun_pool_client.exe start --host 1.2.3.4 --key .\id_ed25519 --no-full-tunnel --route 10.10.0.0/16
  sshtun_pool_client.exe stop

Run start/stop/cleanup from an Administrator PowerShell.`)
}

func defaultOptions() options {
	return options{
		User:               "sshvpn",
		Port:               65523,
		TunStart:           100,
		TunEnd:             200,
		MTU:                1400,
		TunNetA:            10,
		TunNetB:            250,
		FullTunnel:         true,
		SetDNS:             true,
		DNS:                []string{"1.1.1.1", "8.8.8.8"},
		BlockIPv6:          true,
		AdapterName:        defaultAdapterName,
		ConnectTimeoutSec:  10,
		KeepaliveSeconds:   15,
		KeepaliveMisses:    3,
		CleanOrphansOnStop: true,
		RouteStyle:         "gateway",
	}
}

func runStart(args []string) error {
	if err := admin.RequireAdmin(); err != nil {
		return err
	}
	if st, err := loadState(); err == nil {
		if st.PID > 0 && isProcessRunning(st.PID) {
			return fmt.Errorf("VPN already running: pid=%d tun=tun%d adapter=%q. Stop it first: sshtun_pool_client.exe stop", st.PID, st.TunUnit, st.AdapterName)
		}
		log.Printf("found stale state; cleaning it before start")
		cleanupWithState(st, true)
	}

	if err := os.MkdirAll(stateDir(), 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("detect executable path: %w", err)
	}
	logPath := logFilePath()
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logPath, err)
	}
	defer logFile.Close()

	cmd := exec.Command(exe, append([]string{"run"}, args...)...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.Dir = filepath.Dir(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200} // CREATE_NEW_PROCESS_GROUP
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker process: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	log.Printf("starting SSH-TUN worker: pid=%d log=%s", pid, logPath)

	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if !isProcessRunning(pid) {
			return fmt.Errorf("worker process exited before connection was established; see log: %s", logPath)
		}
		if st, err := loadState(); err == nil && st.PID == pid {
			log.Printf("connected: pid=%d tun=tun%d adapter=%q client=%s server=%s", st.PID, st.TunUnit, st.AdapterName, st.ClientIP, st.ServerTunIP)
			log.Printf("Stop: sshtun_pool_client.exe stop")
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("worker pid=%d is still running, but state was not created within timeout; see log: %s", pid, logPath)
}

func runWorker(args []string) error {
	opt, err := parseStartArgs(args)
	if err != nil {
		return err
	}
	if err := admin.RequireAdmin(); err != nil {
		return err
	}
	if opt.RemoteSetupRequested {
		log.Printf("WARNING: --remote-setup is ignored by the Windows client; use a prepared sshvpn server with tun pool/NAT")
	}

	serverIP, err := resolveIPv4(opt.Host)
	if err != nil {
		return err
	}
	log.Printf("server=%s resolved_ip=%s user=%s port=%d", opt.Host, serverIP, opt.User, opt.Port)

	defaultRoute, err := routes.DefaultIPv4Route()
	if err != nil {
		return err
	}
	log.Printf("default route: next_hop=%s if=%s ifIndex=%d", defaultRoute.NextHop, defaultRoute.InterfaceAlias, defaultRoute.InterfaceIndex)

	adapter, err := wintun.CreateOrOpen(opt.AdapterName)
	if err != nil {
		return err
	}
	defer adapter.Close()

	if err := adapter.StartSession(0x800000); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	pool := shuffledRange(opt.TunStart, opt.TunEnd)
	if opt.FixedTun > 0 {
		pool = []int{opt.FixedTun}
	}

	var lastErr error
	for _, unit := range pool {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		pair, err := ipcalc.PairForTun(unit, opt.TunStart, opt.TunNetA, opt.TunNetB)
		if err != nil {
			return err
		}
		log.Printf("trying tun%d: client=%s server=%s", unit, pair.ClientIP, pair.ServerIP)

		dns := opt.DNS
		if !opt.SetDNS {
			dns = nil
		}
		if err := routes.ConfigureAdapter(opt.AdapterName, pair.ClientIP.String(), opt.MTU, dns, opt.BlockIPv6); err != nil {
			return fmt.Errorf("configure adapter: %w", err)
		}
		tunIfIndex, err := routes.InterfaceIndex(opt.AdapterName)
		if err != nil {
			return fmt.Errorf("get adapter ifIndex: %w", err)
		}
		if err := routes.AddServerBypass(serverIP, defaultRoute); err != nil {
			return fmt.Errorf("add server bypass route: %w", err)
		}

		sshClient, err := sshtransport.Dial(ctx, sshtransport.Options{
			Server:            opt.Host,
			Port:              opt.Port,
			User:              opt.User,
			PrivateKeyPath:    expandPath(opt.KeyFile),
			HostKeySHA256:     opt.HostKeySHA256,
			ConnectTimeout:    time.Duration(opt.ConnectTimeoutSec) * time.Second,
			KeepaliveInterval: time.Duration(opt.KeepaliveSeconds) * time.Second,
			KeepaliveMisses:   opt.KeepaliveMisses,
		})
		if err != nil {
			lastErr = err
			routes.CleanupTrafficRoutes(routingMode(opt), tunIfIndex, serverIP, opt.IncludeRoutes, opt.ExcludeRoutes, defaultRoute)
			log.Printf("ssh auth/connect failed: %v", err)
			break
		}

		ch, reqs, err := sshClient.OpenTun(unit)
		if err != nil {
			lastErr = err
			_ = sshClient.Close()
			routes.CleanupTrafficRoutes(routingMode(opt), tunIfIndex, serverIP, opt.IncludeRoutes, opt.ExcludeRoutes, defaultRoute)
			log.Printf("tun%d open failed: %v", unit, err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		if err := routes.ConfigureTrafficRoutes(routingMode(opt), tunIfIndex, pair.ServerIP.String(), opt.IncludeRoutes, opt.ExcludeRoutes, defaultRoute, opt.RouteStyle); err != nil {
			_ = ch.Close()
			_ = sshClient.Close()
			return fmt.Errorf("configure traffic routes: %w", err)
		}

		st := savedState{
			PID:           os.Getpid(),
			AdapterName:   opt.AdapterName,
			ServerIP:      serverIP,
			RoutingMode:   routingMode(opt),
			IncludeRoutes: append([]string(nil), opt.IncludeRoutes...),
			ExcludeRoutes: append([]string(nil), opt.ExcludeRoutes...),
			TunIfIndex:    tunIfIndex,
			DefaultRoute:  defaultRoute,
			TunUnit:       unit,
			ClientIP:      pair.ClientIP.String(),
			ServerTunIP:   pair.ServerIP.String(),
			CreatedAt:     time.Now(),
		}
		_ = saveState(st)

		log.Printf("connected: tun%d adapter=%q client=%s server=%s", unit, opt.AdapterName, pair.ClientIP, pair.ServerIP)
		log.Printf("press Ctrl+C to stop")

		err = packetpump.Run(ctx, adapter, ch)
		log.Printf("packet pump stopped: %v", err)
		_ = ch.Close()
		_ = sshClient.Close()
		adapter.Close()
		cleanupWithState(st, true)
		if err == context.Canceled || ctx.Err() != nil {
			return nil
		}
		return err
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("could not establish SSH-TUN on any tun in %d..%d", opt.TunStart, opt.TunEnd)
}

func parseStartArgs(args []string) (options, error) {
	opt := defaultOptions()
	var routesViaTun, routeFiles, includes, includeFiles, excludes, excludeFiles stringList
	dnsString := strings.Join(opt.DNS, " ")
	routePrivate := false
	excludePrivate := false

	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.StringVar(&opt.Host, "host", "", "SSH-TUN server IP/domain")
	fs.StringVar(&opt.KeyFile, "key", "", "private key file")
	fs.StringVar(&opt.User, "user", opt.User, "SSH user")
	fs.IntVar(&opt.Port, "port", opt.Port, "SSH port")
	fs.IntVar(&opt.FixedTun, "tun", 0, "fixed tun number")
	fs.IntVar(&opt.TunStart, "tun-start", opt.TunStart, "tun pool start")
	fs.IntVar(&opt.TunEnd, "tun-end", opt.TunEnd, "tun pool end")
	fs.IntVar(&opt.MTU, "mtu", opt.MTU, "adapter MTU")
	fs.BoolVar(&routePrivate, "route-private", false, "route private RFC1918 ranges via tunnel")
	fs.BoolVar(&excludePrivate, "exclude-private", false, "bypass private RFC1918 ranges directly")
	fs.Var(&routesViaTun, "route", "route via tunnel; repeatable")
	fs.Var(&routeFiles, "route-file", "route file; repeatable")
	fs.Var(&includes, "include", "alias for --route; repeatable")
	fs.Var(&includeFiles, "include-file", "alias for --route-file; repeatable")
	fs.Var(&excludes, "exclude", "direct/bypass route; repeatable")
	fs.Var(&excludeFiles, "exclude-file", "exclude file; repeatable")
	fs.BoolVar(&opt.FullTunnel, "full-tunnel", opt.FullTunnel, "full tunnel mode")
	fs.BoolFunc("no-full-tunnel", "disable full tunnel mode", func(string) error { opt.FullTunnel = false; return nil })
	fs.BoolFunc("no-dns", "do not configure DNS", func(string) error { opt.SetDNS = false; return nil })
	fs.StringVar(&dnsString, "dns", dnsString, "DNS servers separated by space or comma")
	fs.BoolFunc("no-block-ipv6", "do not disable IPv6 binding", func(string) error { opt.BlockIPv6 = false; return nil })
	fs.BoolFunc("no-clean-orphans", "accepted for Linux compatibility", func(string) error { opt.CleanOrphansOnStop = false; return nil })
	fs.BoolVar(&opt.AskPassphrase, "ask-passphrase", false, "accepted; encrypted keys prompt automatically")
	fs.StringVar(&opt.AdapterName, "adapter-name", opt.AdapterName, "Windows Wintun adapter name")
	fs.StringVar(&opt.HostKeySHA256, "host-key-sha256", "", "SSH host key SHA256 fingerprint pin")
	fs.StringVar(&opt.RouteStyle, "route-style", opt.RouteStyle, "Windows route style: onlink or gateway")
	fs.BoolVar(&opt.RemoteSetupRequested, "remote-setup", false, "ignored on Windows client")
	fs.IntVar(&opt.ConnectTimeoutSec, "connect-timeout", opt.ConnectTimeoutSec, "SSH connect timeout seconds")
	fs.IntVar(&opt.KeepaliveSeconds, "keepalive-seconds", opt.KeepaliveSeconds, "SSH keepalive interval seconds")
	fs.IntVar(&opt.KeepaliveMisses, "keepalive-misses", opt.KeepaliveMisses, "SSH keepalive max misses")
	if err := fs.Parse(args); err != nil {
		return opt, err
	}

	opt.KeyFile = expandPath(opt.KeyFile)
	opt.IncludeRoutes = append(opt.IncludeRoutes, routesViaTun...)
	opt.IncludeRoutes = append(opt.IncludeRoutes, includes...)
	opt.IncludeFiles = append(opt.IncludeFiles, routeFiles...)
	opt.IncludeFiles = append(opt.IncludeFiles, includeFiles...)
	opt.ExcludeRoutes = append(opt.ExcludeRoutes, excludes...)
	opt.ExcludeFiles = append(opt.ExcludeFiles, excludeFiles...)
	if routePrivate {
		opt.IncludeRoutes = append(opt.IncludeRoutes, privateCIDRs()...)
	}
	if excludePrivate {
		opt.ExcludeRoutes = append(opt.ExcludeRoutes, privateCIDRs()...)
	}
	opt.DNS = parseDNS(dnsString)

	if err := expandRouteFiles(&opt); err != nil {
		return opt, err
	}
	normalizeRoutes(&opt)
	if err := validateStartOptions(opt); err != nil {
		return opt, err
	}
	return opt, nil
}

func validateStartOptions(opt options) error {
	if strings.TrimSpace(opt.Host) == "" {
		return fmt.Errorf("--host is required")
	}
	if strings.TrimSpace(opt.KeyFile) == "" {
		return fmt.Errorf("--key is required")
	}
	if _, err := os.Stat(opt.KeyFile); err != nil {
		return fmt.Errorf("key file not found: %s: %w", opt.KeyFile, err)
	}
	if opt.Port <= 0 || opt.Port > 65535 {
		return fmt.Errorf("bad --port: %d", opt.Port)
	}
	if opt.TunStart < 0 || opt.TunEnd < opt.TunStart {
		return fmt.Errorf("bad tun pool: %d..%d", opt.TunStart, opt.TunEnd)
	}
	if opt.FixedTun != 0 && (opt.FixedTun < opt.TunStart || opt.FixedTun > opt.TunEnd) {
		return fmt.Errorf("--tun must be inside pool")
	}
	if opt.MTU < 576 || opt.MTU > 9000 {
		return fmt.Errorf("bad --mtu: %d", opt.MTU)
	}
	optRouteStyle := strings.ToLower(strings.TrimSpace(opt.RouteStyle))
	if optRouteStyle != "onlink" && optRouteStyle != "gateway" {
		return fmt.Errorf("bad --route-style: %s; use onlink or gateway", opt.RouteStyle)
	}
	for _, cidr := range append(append([]string{}, opt.IncludeRoutes...), opt.ExcludeRoutes...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("bad CIDR %q: %w", cidr, err)
		}
	}
	return nil
}

func runStop(args []string) error {
	adapterName := parseAdapterNameForStop(args)
	if err := admin.RequireAdmin(); err != nil {
		return err
	}
	st, err := loadState()
	if err != nil {
		log.Printf("No state file")
		log.Printf("Cleaning adapter %q anyway", adapterName)
		routes.CleanupAdapter(adapterName, true)
		log.Printf("Stopped")
		return nil
	}
	if st.AdapterName != "" {
		adapterName = st.AdapterName
	}
	if st.PID > 0 && isProcessRunning(st.PID) {
		log.Printf("Stopping SSH-TUN worker: pid=%d tun=tun%d adapter=%q", st.PID, st.TunUnit, adapterName)
		if err := killProcessTree(st.PID); err != nil {
			log.Printf("WARNING: could not kill pid=%d: %v", st.PID, err)
		}
		waitProcessGone(st.PID, 5*time.Second)
	} else {
		log.Printf("State exists, but process is not running or pid is missing")
	}
	cleanupWithState(st, true)
	log.Printf("Stopped")
	return nil
}

func parseAdapterNameForStop(args []string) string {
	adapterName := defaultAdapterName
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--adapter-name":
			if i+1 < len(args) {
				adapterName = args[i+1]
				i++
			}
		case "--host", "--key", "--user", "--port", "--tun", "--tun-start", "--tun-end", "--mtu", "--dns", "--route", "--route-file", "--include", "--include-file", "--exclude", "--exclude-file", "--host-key-sha256":
			if i+1 < len(args) {
				i++
			}
		default:
			// Ignore Linux-compatible flags for stop/cleanup.
		}
	}
	return adapterName
}

func cleanupWithState(st savedState, deleteState bool) {
	dr := st.DefaultRoute
	if dr.InterfaceIndex == 0 {
		if cur, err := routes.DefaultIPv4Route(); err == nil {
			dr = cur
		}
	}
	if st.TunIfIndex > 0 {
		routes.CleanupTrafficRoutes(st.RoutingMode, st.TunIfIndex, st.ServerIP, st.IncludeRoutes, st.ExcludeRoutes, dr)
	}
	routes.CleanupAdapter(st.AdapterName, true)
	if deleteState {
		_ = os.Remove(stateFilePath())
	}
	log.Printf("cleanup completed for adapter %q", st.AdapterName)
}

func runStatus(args []string) error {
	adapterName := parseAdapterNameForStop(args)
	st, err := loadState()
	if err == nil {
		running := st.PID > 0 && isProcessRunning(st.PID)
		if running {
			fmt.Println("Status: running")
		} else {
			fmt.Println("Status: stale state, worker process is not running")
			fmt.Println("Run: sshtun_pool_client.exe stop")
		}
		fmt.Printf("PID: %d\n", st.PID)
		fmt.Printf("Adapter: %s\n", st.AdapterName)
		fmt.Printf("TUN: tun%d\n", st.TunUnit)
		fmt.Printf("Client IP: %s\n", st.ClientIP)
		fmt.Printf("Server TUN IP: %s\n", st.ServerTunIP)
		fmt.Printf("Server IP: %s\n", st.ServerIP)
		adapterName = st.AdapterName
	} else {
		fmt.Println("Status: stopped")
	}
	out, _ := routes.AdapterStatus(adapterName)
	if strings.TrimSpace(out) != "" {
		fmt.Println(out)
	}
	return nil
}

func runDoctor(args []string) error {
	adapterName := parseAdapterNameForStop(args)
	st, err := loadState()
	fmt.Println("== state ==")
	if err == nil {
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(b))
		adapterName = st.AdapterName
	} else {
		fmt.Println("no saved state")
	}
	fmt.Println("\n== adapter/routes ==")
	out, err := routes.Doctor(adapterName)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	fmt.Println(out)
	return nil
}

func routingMode(opt options) string {
	if opt.FullTunnel {
		return "full"
	}
	return "split"
}

func parseDNS(v string) []string {
	v = strings.ReplaceAll(v, ",", " ")
	fields := strings.Fields(v)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func privateCIDRs() []string {
	return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
}

func expandRouteFiles(opt *options) error {
	for _, f := range opt.IncludeFiles {
		rs, err := readCIDRFile(expandPath(f))
		if err != nil {
			return err
		}
		opt.IncludeRoutes = append(opt.IncludeRoutes, rs...)
	}
	for _, f := range opt.ExcludeFiles {
		rs, err := readCIDRFile(expandPath(f))
		if err != nil {
			return err
		}
		opt.ExcludeRoutes = append(opt.ExcludeRoutes, rs...)
	}
	return nil
}

func readCIDRFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open route file %s: %w", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func normalizeRoutes(opt *options) {
	opt.IncludeRoutes = dedupeCIDRs(opt.IncludeRoutes)
	opt.ExcludeRoutes = dedupeCIDRs(opt.ExcludeRoutes)
}

func dedupeCIDRs(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func shuffledRange(start, end int) []int {
	n := end - start + 1
	out := make([]int, n)
	for i := 0; i < n; i++ {
		out[i] = start + i
	}
	rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func resolveIPv4(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %s", host)
}

func expandPath(p string) string {
	p = os.ExpandEnv(strings.TrimSpace(p))
	if p == "" {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func stateDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, appStateDirName)
}

func stateFilePath() string { return filepath.Join(stateDir(), "state.json") }
func logFilePath() string   { return filepath.Join(stateDir(), "sshtun.log") }

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", fmt.Sprintf("$p = Get-Process -Id %d -ErrorAction SilentlyContinue; if ($null -eq $p) { exit 1 } else { exit 0 }", pid))
	return cmd.Run() == nil
}

func killProcessTree(pid int) error {
	if pid <= 0 {
		return nil
	}
	cmd := exec.Command("taskkill.exe", "/PID", fmt.Sprintf("%d", pid), "/T", "/F")
	out, err := cmd.CombinedOutput()
	if err != nil && isProcessRunning(pid) {
		return fmt.Errorf("taskkill failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func waitProcessGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isProcessRunning(pid) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return !isProcessRunning(pid)
}

func saveState(st savedState) error {
	if err := os.MkdirAll(stateDir(), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFilePath(), b, 0600)
}

func loadState() (savedState, error) {
	var st savedState
	b, err := os.ReadFile(stateFilePath())
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	if st.AdapterName == "" {
		st.AdapterName = defaultAdapterName
	}
	return st, nil
}
