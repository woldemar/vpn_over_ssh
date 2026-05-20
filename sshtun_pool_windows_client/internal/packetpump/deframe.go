package packetpump

import (
	"fmt"
	"io"

	"sshtun_pool_client/internal/ipcalc"
)

type Deframer struct {
	r   io.Reader
	buf []byte
}

func NewDeframer(r io.Reader) *Deframer {
	return &Deframer{r: r, buf: make([]byte, 0, 128*1024)}
}

func (d *Deframer) Next() ([]byte, error) {
	for {
		if n, ok := packetLength(d.buf); ok {
			pkt := make([]byte, n)
			copy(pkt, d.buf[:n])
			d.buf = d.buf[n:]
			return pkt, nil
		}

		tmp := make([]byte, 8192)
		n, err := d.r.Read(tmp)
		if n > 0 {
			d.buf = append(d.buf, tmp[:n]...)
			if len(d.buf) > 2*1024*1024 {
				return nil, fmt.Errorf("deframer buffer too large; packet boundaries are broken")
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

func packetLength(buf []byte) (int, bool) {
	if len(buf) < 1 {
		return 0, false
	}
	switch buf[0] >> 4 {
	case 4:
		if len(buf) < 20 {
			return 0, false
		}
		n, ok := ipcalc.IPv4TotalLength(buf)
		if !ok || len(buf) < n {
			return 0, false
		}
		return n, true
	case 6:
		if len(buf) < 40 {
			return 0, false
		}
		n, ok := ipcalc.IPv6PayloadTotalLength(buf)
		if !ok || len(buf) < n {
			return 0, false
		}
		return n, true
	default:
		// Drop one bad byte and let caller retry. This helps recover from stream noise.
		return 1, len(buf) >= 1
	}
}
