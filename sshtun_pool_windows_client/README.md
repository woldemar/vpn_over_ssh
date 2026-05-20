# sshtun_pool_client for Windows

Windows SSH-TUN client prototype in Go + Wintun DLL.

The command-line syntax is aligned with the Linux client. There is no JSON config requirement. You pass the SSH key and options directly on the command line.

## Server assumptions

The server is already prepared with a dedicated SSH-TUN service:

- user: `sshvpn`
- port: `65523`
- `PermitTunnel point-to-point`
- prepared tun pool, for example `tun100..tun200`
- NAT/forwarding enabled for `10.250.0.0/16`

This Windows client expects the server-side tun pool to already exist.

## Build

Run PowerShell as a normal user for build:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\build.ps1
```

The build script downloads `wintun.dll` from `wintun.net`, resolves Go modules, and creates:

```text
dist\sshtun_pool_client.exe
dist\wintun.dll
```

## Start / stop behavior

`start` now behaves like the Linux client: it launches a background worker, waits until the tunnel is connected, saves state in `C:\ProgramData\sshtun_pool_client\state.json`, then exits. Runtime logs are written to `C:\ProgramData\sshtun_pool_client\sshtun.log`.

If a worker is already running, a second `start` reports that the VPN is already running and does not start another tunnel.

Run PowerShell as Administrator:

```powershell
.\dist\sshtun_pool_client.exe start --host 1.2.3.4 --key .\id_ed25519
```

With explicit Linux-compatible options:

```powershell
.\dist\sshtun_pool_client.exe start `
  --host 1.2.3.4 `
  --user sshvpn `
  --port 65523 `
  --key .\id_ed25519 `
  --tun-start 100 `
  --tun-end 200 `
  --mtu 1400
```

## Full tunnel with excludes

```powershell
.\dist\sshtun_pool_client.exe start `
  --host 1.2.3.4 `
  --key .\id_ed25519 `
  --exclude-private
```

Or manually:

```powershell
.\dist\sshtun_pool_client.exe start `
  --host 1.2.3.4 `
  --key .\id_ed25519 `
  --exclude 192.168.0.0/16 `
  --exclude 10.0.0.0/8 `
  --exclude 172.16.0.0/12
```

## Split tunnel

```powershell
.\dist\sshtun_pool_client.exe start `
  --host 1.2.3.4 `
  --key .\id_ed25519 `
  --no-full-tunnel `
  --route 10.10.0.0/16 `
  --route 172.20.0.0/16
```

Large route lists can be placed into files, one CIDR per line:

```powershell
.\dist\sshtun_pool_client.exe start --host 1.2.3.4 --key .\id_ed25519 --exclude-file .\ru-cidrs.txt
```

## Stop / cleanup / diagnostics

```powershell
.\dist\sshtun_pool_client.exe stop
.\dist\sshtun_pool_client.exe cleanup
.\dist\sshtun_pool_client.exe status
.\dist\sshtun_pool_client.exe doctor
```

## Supported Linux-compatible options

```text
--host HOST
--key FILE
--user USER
--port PORT
--tun N
--tun-start N
--tun-end N
--mtu N
--no-full-tunnel
--route CIDR
--route-file FILE
--include CIDR
--include-file FILE
--exclude CIDR
--exclude-file FILE
--route-private
--exclude-private
--no-dns
--dns "1.1.1.1 8.8.8.8"
--no-block-ipv6
--no-clean-orphans
--ask-passphrase
```

Windows-specific optional flags:

```text
--adapter-name "SSHTUN Pool"
--host-key-sha256 SHA256:...
--route-style gateway|onlink
```

Encrypted private keys are supported. The client prompts for the passphrase automatically when needed.

## v9 lifecycle notes

New behavior:

```powershell
.\dist\sshtun_pool_client.exe start   # starts background worker and exits after connect
.\dist\sshtun_pool_client.exe status  # shows PID/tun/client/server IP
.\dist\sshtun_pool_client.exe stop    # kills worker, removes routes/DNS/IP and state
.\dist\sshtun_pool_client.exe cleanup # same cleanup path, useful after crashes
```

A stale state file is cleaned automatically before a new start.

## v8/v9 performance notes

This build uses the working OpenSSH `tun@openssh.com` framing: every channel payload is `uint32 address_family + raw IP packet`. It also changes the local TUN backend from a direct raw `wintun.dll` wrapper to `golang.zx2c4.com/wireguard/tun`, which avoids the previous polling loop and generally gives better throughput on Windows.

Other performance changes:

- default MTU returned to `1400`;
- SSH TCP socket uses `TCP_NODELAY` and larger read/write buffers;
- fast cipher preference: AES-GCM first, then chacha20;
- useless IPv4 multicast/broadcast/link-local chatter is not forwarded into SSH.

If some networks still stall, try `--mtu 1360` or `--mtu 1280`.
