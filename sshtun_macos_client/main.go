// sshtun-macos-tun — L3 data plane для macOS-бэкенда vpn_over_ssh.
//
// Заменяет «ssh -w», который на современной macOS невозможен (ни Apple ssh,
// ни portable OpenSSH не поддерживают utun; /dev/tun не существует).
// Реализует wire-протокол OpenSSH tun@openssh.com в userspace:
//
//	channel open "tun@openssh.com", payload = {uint32 Mode=1, uint32 Unit}
//	каждый кадр канала = uint32 address_family (2=inet, 24=inet6) + IP-пакет
//
// Локальная сторона — utun через golang.zx2c4.com/wireguard/tun (kernel
// создаёт utun-N). Адреса/MTU/mаршрутная политика НЕ трогаем: их накладывает
// sshtun_macos.sh (ifconfig + pfctl) — этот процесс только гоняет пакеты и
// печатает в stdout маркер UTUN_READY после установления канала.
//
// Запуск (от root, досматривается бэкендом):
//
//	sshtun-macos-tun --host H --port P --user U --key FILE \
//	  --remote-unit N --mtu 1400 --known-hosts FILE
//
// Код pump/deframe/framing адаптирован из sshtun_pool_windows_client
// (тот же репозиторий) — Windows-часть (wintun) заменена на utun.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	sshTunAFInet  = 2
	sshTunAFInet6 = 24
	maxPacket     = 65535
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("[tun] ")

	host := flag.String("host", "", "server address (required)")
	port := flag.Int("port", 65523, "server ssh port")
	user := flag.String("user", "sshvpn", "ssh user")
	keyFile := flag.String("key", "", "private key path (required)")
	remoteUnit := flag.Int("remote-unit", 0, "server-side tun unit N (required)")
	mtu := flag.Int("mtu", 1400, "tun MTU")
	knownHosts := flag.String("known-hosts", "", "known_hosts file (accept-new semantics)")
	timeout := flag.Duration("timeout", 20*time.Second, "ssh connect timeout")
	flag.Parse()

	if *host == "" || *keyFile == "" || *remoteUnit <= 0 {
		flag.Usage()
		os.Exit(2)
	}

	// 1) utun: создаём ДО ssh, чтобы бэкенд видел устройство даже при
	// медленной аутентификации; имя печатаем в UTUN_READY после канала.
	// MTU применяет бэкенд через ifconfig — здесь только гоняем пакеты.
	dev, err := createUtun()
	if err != nil {
		log.Fatalf("utun create failed: %v", err)
	}
	defer dev.Close()
	ifName := dev.Name()
	log.Printf("utun created: %s (mtu=%d применит ifconfig бэкенда)", ifName, *mtu)

	// 2) ssh
	signer, err := loadSigner(*keyFile)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	cb, err := hostKeyCallback(*knownHosts)
	if err != nil {
		log.Fatalf("known-hosts: %v", err)
	}
	cfg := &ssh.ClientConfig{
		User:            *user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         *timeout,
		ClientVersion:   "SSH-2.0-sshtun_macos_tun",
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
				"aes128-ctr",
			},
		},
	}
	addr := net.JoinHostPort(*host, fmt.Sprintf("%d", *port))
	sshClient, err := dial(addr, cfg, *timeout)
	if err != nil {
		log.Fatalf("ssh dial %s: %v", addr, err)
	}
	go keepalive(sshClient, 10*time.Second, 3)

	// 3) канал tun@openssh.com: payload {Mode=1 point-to-point, Unit=N}
	payload := ssh.Marshal(struct {
		Mode uint32
		Unit uint32
	}{Mode: 1, Unit: uint32(*remoteUnit)})
	ch, reqs, err := sshClient.OpenChannel("tun@openssh.com", payload)
	if err != nil {
		log.Fatalf("open tun@openssh.com unit=%d: %v", *remoteUnit, err)
	}
	go func() { // служебные запросы канала не поддерживаем
		for r := range reqs {
			_ = r.Reply(false, nil)
		}
	}()
	log.Printf("ssh channel open: tun@openssh.com unit=%d", *remoteUnit)

	// 4) маркер для бэкенда: устройство готово к ifconfig/pf
	fmt.Printf("UTUN_READY dev=%s remote_unit=%d\n", ifName, *remoteUnit)

	// 5) pump
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = pump(ctx, dev, ch)
	log.Printf("pump ended: %v", err)
	_ = ch.Close()
	sshClient.Close()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
		os.Exit(1)
	}
}

// dial: tcp + ssh handshake (NewClientConn) с настройками производительности.
func dial(addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetReadBuffer(4 << 20)
		_ = tcp.SetWriteBuffer(4 << 20)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func loadSigner(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		// passphrase-защищённые ключи не поддерживаем (наша модель — ключ без passphrase)
		var pp *ssh.PassphraseMissingError
		if errors.As(err, &pp) {
			return nil, fmt.Errorf("ключ защищён passphrase — создайте ключ без неё: %s", path)
		}
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return s, nil
}

// hostKeyCallback: pin по SHA256 (если задан через файла не нужен) — у нас
// accept-new: известные хосты проверяем строго, неизвестный — принимаем и
// дописываем в файл (как StrictHostKeyChecking=accept-new).
func hostKeyCallback(knownHostsPath string) (ssh.HostKeyCallback, error) {
	if knownHostsPath == "" {
		return nil, fmt.Errorf("--known-hosts обязателен")
	}
	kh, err := knownhosts.New(knownHostsPath)
	if err != nil {
		// файла ещё нет — создадим при первом accept
		if !os.IsNotExist(err) {
			return nil, err
		}
		kh = nil
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if kh != nil {
			err := kh(hostname, remote, key)
			if err == nil {
				return nil
			}
			var kf *knownhosts.KeyError
			if !errors.As(err, &kf) || len(kf.Want) > 0 {
				// изменился ключ известного хоста — строго отказ
				return err
			}
			// хост неизвестен — accept-new: дописываем
		}
		f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("known_hosts append: %w", err)
		}
		defer f.Close()
		_, err = f.WriteString(knownhosts.Line([]string{hostname}, key) + "\n")
		if err != nil {
			return fmt.Errorf("known_hosts append: %w", err)
		}
		// перечитываем для последующих проверок в рамках процесса
		if kh2, err2 := knownhosts.New(knownHostsPath); err2 == nil {
			kh = kh2
		}
		return nil
	}, nil
}

func keepalive(c *ssh.Client, interval time.Duration, maxMisses int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	misses := 0
	for range t.C {
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			misses++
			if misses >= maxMisses {
				_ = c.Close()
				return
			}
			continue
		}
		misses = 0
	}
}

// pump гоняет пакеты utun <-> канал до первой ошибки любого направления.
func pump(ctx context.Context, dev *utunDevice, ch ssh.Channel) error {
	errCh := make(chan error, 2)

	// utun -> ssh
	go func() {
		for {
			pkt, err := dev.Read()
			if err != nil {
				errCh <- err
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if len(pkt) == 0 {
				continue
			}
			var af uint32
			switch pkt[0] >> 4 {
			case 4:
				af = sshTunAFInet
			case 6:
				af = sshTunAFInet6
			default:
				continue // мусор
			}
			frame := make([]byte, 4+len(pkt))
			binary.BigEndian.PutUint32(frame[:4], af)
			copy(frame[4:], pkt)
			if _, err := ch.Write(frame); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// ssh -> utun
	go func() {
		pending := make([]byte, 0, 256*1024)
		tmp := make([]byte, 64*1024)
		for {
			n, err := ch.Read(tmp)
			if n > 0 {
				pending = append(pending, tmp[:n]...)
				if len(pending) > 2*1024*1024 {
					errCh <- fmt.Errorf("deframe buffer too large")
					return
				}
			}
			for {
				pkt, rest, ok := consumeFrame(pending)
				if !ok {
					break
				}
				pending = rest
				if len(pkt) > 0 {
					if werr := dev.Write(pkt); werr != nil {
						errCh <- werr
						return
					}
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// consumeFrame вырезает один кадр tun@openssh.com из буфера:
// uint32 AF + IP-пакет (длина берётся из заголовка IP).
func consumeFrame(pending []byte) (pkt []byte, rest []byte, ok bool) {
	for len(pending) >= 4 {
		af := binary.BigEndian.Uint32(pending[:4])
		body := pending[4:]
		switch af {
		case sshTunAFInet:
			if len(body) < 20 {
				return nil, pending, false
			}
			if body[0]>>4 != 4 {
				// рассинхрон: пропускаем байт
				pending = pending[1:]
				continue
			}
			total := int(binary.BigEndian.Uint16(body[2:4]))
			ihl := int(body[0]&0x0f) * 4
			if ihl < 20 || total < ihl {
				pending = pending[1:]
				continue
			}
			if len(body) < total {
				return nil, pending, false
			}
			return body[:total], pending[4+total:], true
		case sshTunAFInet6:
			if len(body) < 40 {
				return nil, pending, false
			}
			if body[0]>>4 != 6 {
				pending = pending[1:]
				continue
			}
			total := 40 + int(binary.BigEndian.Uint16(body[4:6]))
			if len(body) < total {
				return nil, pending, false
			}
			return body[:total], pending[4+total:], true
		default:
			pending = pending[1:]
			continue
		}
	}
	return nil, pending, false
}
