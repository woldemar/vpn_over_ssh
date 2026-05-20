package packetpump

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sshTunAFInet  = 2
	sshTunAFInet6 = 24
	maxTunPacket  = 65535
)

type Tun interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
}

type Stats struct {
	TunToSSHBytes uint64
	SSHToTunBytes uint64
	TunToSSHPkts  uint64
	SSHToTunPkts  uint64
	Errors        uint64
}

func ipSummary(pkt []byte) string {
	if len(pkt) < 1 {
		return "empty"
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return fmt.Sprintf("ipv4 short len=%d", len(pkt))
		}
		proto := pkt[9]
		src := fmt.Sprintf("%d.%d.%d.%d", pkt[12], pkt[13], pkt[14], pkt[15])
		dst := fmt.Sprintf("%d.%d.%d.%d", pkt[16], pkt[17], pkt[18], pkt[19])
		total := int(pkt[2])<<8 | int(pkt[3])
		extra := ""
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) >= ihl+4 && (proto == 6 || proto == 17) {
			sp := int(pkt[ihl])<<8 | int(pkt[ihl+1])
			dp := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
			extra = fmt.Sprintf(" %d->%d", sp, dp)
		}
		return fmt.Sprintf("ipv4 len=%d total=%d proto=%d %s->%s%s", len(pkt), total, proto, src, dst, extra)
	case 6:
		if len(pkt) < 40 {
			return fmt.Sprintf("ipv6 short len=%d", len(pkt))
		}
		plen := int(pkt[4])<<8 | int(pkt[5])
		proto := pkt[6]
		return fmt.Sprintf("ipv6 len=%d payload=%d proto=%d", len(pkt), plen, proto)
	default:
		return fmt.Sprintf("unknown first=0x%02x len=%d", pkt[0], len(pkt))
	}
}

func isIPv4Noise(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	// Drop multicast/broadcast/link-local chatter that is useless for an IPv4
	// internet tunnel and can noticeably waste upload on Windows.
	d0, d1, d2, d3 := pkt[16], pkt[17], pkt[18], pkt[19]
	if d0 >= 224 && d0 <= 239 {
		return true
	}
	if d0 == 255 && d1 == 255 && d2 == 255 && d3 == 255 {
		return true
	}
	if d0 == 169 && d1 == 254 {
		return true
	}
	return false
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func writeOpenSSHTunPacket(w io.Writer, pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	var af uint32
	switch pkt[0] >> 4 {
	case 4:
		af = sshTunAFInet
	case 6:
		af = sshTunAFInet6
	default:
		return fmt.Errorf("not an IP packet: first byte 0x%02x", pkt[0])
	}

	// OpenSSH tun@openssh.com channel payload for L3 mode is:
	//   uint32 address_family
	//   byte[] ip_packet
	// x/crypto/ssh already wraps this payload into SSH_MSG_CHANNEL_DATA as an
	// SSH string. Do not add an extra packet_length here.
	frame := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(frame[0:4], af)
	copy(frame[4:], pkt)
	return writeFull(w, frame)
}

func consumeOpenSSHTunFrame(pending []byte) (uint32, []byte, int, bool, error) {
	if len(pending) < 4 {
		return 0, nil, 0, false, nil
	}
	af := binary.BigEndian.Uint32(pending[0:4])
	pkt := pending[4:]
	switch af {
	case sshTunAFInet:
		if len(pkt) < 20 {
			return 0, nil, 0, false, nil
		}
		if pkt[0]>>4 != 4 {
			return 0, nil, 1, true, nil
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return 0, nil, 0, false, nil
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen < ihl || totalLen > maxTunPacket {
			return 0, nil, 1, true, nil
		}
		if len(pkt) < totalLen {
			return 0, nil, 0, false, nil
		}
		return af, pkt[:totalLen], 4 + totalLen, true, nil
	case sshTunAFInet6:
		if len(pkt) < 40 {
			return 0, nil, 0, false, nil
		}
		if pkt[0]>>4 != 6 {
			return 0, nil, 1, true, nil
		}
		totalLen := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		if totalLen > maxTunPacket {
			return 0, nil, 1, true, nil
		}
		if len(pkt) < totalLen {
			return 0, nil, 0, false, nil
		}
		return af, pkt[:totalLen], 4 + totalLen, true, nil
	default:
		return 0, nil, 1, true, nil
	}
}

func Run(ctx context.Context, tun Tun, sshrw io.ReadWriter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var st Stats
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	sendErr := func(err error) {
		if err == nil {
			return
		}
		atomic.AddUint64(&st.Errors, 1)
		select {
		case errCh <- err:
		default:
		}
		cancel()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		droppedNonIPv4 := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pkt, err := tun.ReadPacket()
			if err != nil {
				sendErr(err)
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if pkt[0]>>4 != 4 {
				if droppedNonIPv4 < 10 {
					log.Printf("debug drop non-ipv4 tun->ssh: %s", ipSummary(pkt))
				}
				droppedNonIPv4++
				continue
			}
			if isIPv4Noise(pkt) {
				continue
			}
			curPkt := atomic.LoadUint64(&st.TunToSSHPkts)
			if curPkt < 32 {
				log.Printf("debug packet tun->ssh: %s", ipSummary(pkt))
			}
			if err := writeOpenSSHTunPacket(sshrw, pkt); err != nil {
				sendErr(err)
				return
			}
			atomic.AddUint64(&st.TunToSSHPkts, 1)
			atomic.AddUint64(&st.TunToSSHBytes, uint64(len(pkt)))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		droppedNonIPv4 := 0
		badFrames := 0
		buf := make([]byte, 65539)
		pending := make([]byte, 0, 131072)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := sshrw.Read(buf)
			if err != nil {
				if ctx.Err() != nil || err == io.EOF {
					return
				}
				sendErr(err)
				return
			}
			if n <= 0 {
				continue
			}
			pending = append(pending, buf[:n]...)
			if len(pending) > 2*1024*1024 {
				sendErr(fmt.Errorf("ssh->tun deframe buffer too large"))
				return
			}
			for len(pending) > 0 {
				af, pkt, consumed, ok, err := consumeOpenSSHTunFrame(pending)
				if err != nil {
					sendErr(err)
					return
				}
				if !ok {
					break
				}
				if consumed <= 0 || consumed > len(pending) {
					sendErr(fmt.Errorf("bad openssh tun consumed length: %d", consumed))
					return
				}
				pending = pending[consumed:]
				if af != sshTunAFInet || len(pkt) < 20 || pkt[0]>>4 != 4 {
					if droppedNonIPv4 < 10 {
						log.Printf("debug drop non-ipv4 ssh->tun: af=%d %s", af, ipSummary(pkt))
					}
					droppedNonIPv4++
					continue
				}
				if consumed == 1 && badFrames < 10 {
					badFrames++
					log.Printf("debug bad ssh->tun frame byte skipped")
				}
				curPkt := atomic.LoadUint64(&st.SSHToTunPkts)
				if curPkt < 32 {
					log.Printf("debug packet ssh->tun: %s", ipSummary(pkt))
				}
				if err := tun.WritePacket(pkt); err != nil {
					sendErr(err)
					return
				}
				atomic.AddUint64(&st.SSHToTunPkts, 1)
				atomic.AddUint64(&st.SSHToTunBytes, uint64(len(pkt)))
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("stats tun->ssh pkts=%d bytes=%d ssh->tun pkts=%d bytes=%d errors=%d",
					atomic.LoadUint64(&st.TunToSSHPkts), atomic.LoadUint64(&st.TunToSSHBytes),
					atomic.LoadUint64(&st.SSHToTunPkts), atomic.LoadUint64(&st.SSHToTunBytes),
					atomic.LoadUint64(&st.Errors))
			}
		}
	}()

	var ret error
	select {
	case <-ctx.Done():
		ret = ctx.Err()
	case err := <-errCh:
		ret = err
		cancel()
	}
	if closer, ok := sshrw.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	if closer, ok := tun.(interface{ Close() }); ok {
		closer.Close()
	}
	wg.Wait()
	return ret
}
