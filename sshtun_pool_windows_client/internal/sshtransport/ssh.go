package sshtransport

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Options struct {
	Server            string
	Port              int
	User              string
	PrivateKeyPath    string
	PrivateKeyPEM     string
	Passphrase        string
	HostKeySHA256     string
	ConnectTimeout    time.Duration
	KeepaliveInterval time.Duration
	KeepaliveMisses   int
}

type Client struct {
	SSH *ssh.Client
}

func Dial(ctx context.Context, opt Options) (*Client, error) {
	signer, err := loadSigner(opt)
	if err != nil {
		return nil, err
	}
	if opt.ConnectTimeout == 0 {
		opt.ConnectTimeout = 10 * time.Second
	}
	addr := net.JoinHostPort(opt.Server, fmt.Sprintf("%d", opt.Port))

	cb := hostKeyCallback(opt.HostKeySHA256)
	cfg := &ssh.ClientConfig{
		User:            opt.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         opt.ConnectTimeout,
		ClientVersion:   "SSH-2.0-sshtun_pool_client",
		Config: ssh.Config{
			// Prefer fast modern ciphers. On most x86 Windows laptops AES-GCM is
			// hardware accelerated; chacha20 remains a good fallback.
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
				"aes128-ctr",
			},
		},
	}

	type result struct {
		c   *ssh.Client
		err error
	}
	ch := make(chan result, 1)
	go func() {
		dialer := net.Dialer{Timeout: opt.ConnectTimeout, KeepAlive: 30 * time.Second}
		netConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			ch <- result{err: err}
			return
		}
		if tcp, ok := netConn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(30 * time.Second)
			_ = tcp.SetReadBuffer(4 * 1024 * 1024)
			_ = tcp.SetWriteBuffer(4 * 1024 * 1024)
		}
		sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, cfg)
		if err != nil {
			_ = netConn.Close()
			ch <- result{err: err}
			return
		}
		ch <- result{c: ssh.NewClient(sshConn, chans, reqs)}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		cl := &Client{SSH: r.c}
		if opt.KeepaliveInterval > 0 {
			misses := opt.KeepaliveMisses
			if misses <= 0 {
				misses = 3
			}
			go cl.keepalive(opt.KeepaliveInterval, misses)
		}
		return cl, nil
	}
}

func (c *Client) Close() error {
	if c == nil || c.SSH == nil {
		return nil
	}
	return c.SSH.Close()
}

func (c *Client) OpenTun(unit int) (ssh.Channel, <-chan *ssh.Request, error) {
	payload := ssh.Marshal(struct {
		Mode uint32
		Unit uint32
	}{Mode: 1, Unit: uint32(unit)})
	return c.SSH.OpenChannel("tun@openssh.com", payload)
}

func (c *Client) keepalive(interval time.Duration, maxMisses int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	misses := 0
	for range t.C {
		_, _, err := c.SSH.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			misses++
			log.Printf("ssh keepalive miss %d/%d: %v", misses, maxMisses, err)
			if misses >= maxMisses {
				_ = c.SSH.Close()
				return
			}
			continue
		}
		misses = 0
	}
}

func loadSigner(opt Options) (ssh.Signer, error) {
	var key []byte
	if strings.TrimSpace(opt.PrivateKeyPEM) != "" {
		key = []byte(opt.PrivateKeyPEM)
	} else {
		b, err := os.ReadFile(opt.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		key = b
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err == nil {
		return signer, nil
	}

	if opt.Passphrase == "" {
		fmt.Print("Private key passphrase: ")
		pw, pwErr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if pwErr != nil {
			return nil, pwErr
		}
		opt.Passphrase = string(pw)
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(opt.Passphrase))
	if err != nil {
		return nil, fmt.Errorf("parse private key with passphrase: %w", err)
	}
	return signer, nil
}

func hostKeyCallback(pin string) ssh.HostKeyCallback {
	pin = strings.TrimSpace(pin)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if pin == "" {
			log.Printf("WARNING: host_key_sha256 is empty; accepting server host key %s for %s", fp, hostname)
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(fp), []byte(pin)) != 1 {
			return fmt.Errorf("host key mismatch for %s: got %s expected %s", hostname, fp, pin)
		}
		return nil
	}
}
