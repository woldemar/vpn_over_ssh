package ipcalc

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

type Pair struct {
	TunNum   int
	ClientIP net.IP
	ServerIP net.IP
}

func PairForTun(tunNum, poolStart, netA, netB int) (Pair, error) {
	offset := tunNum - poolStart
	if offset < 0 {
		return Pair{}, fmt.Errorf("tun %d is below pool start %d", tunNum, poolStart)
	}
	base := offset * 4
	oct3 := base / 256
	oct4 := base % 256
	if oct3 > 255 || oct4 > 253 {
		return Pair{}, fmt.Errorf("pool does not fit into %d.%d.0.0/16", netA, netB)
	}
	return Pair{
		TunNum:   tunNum,
		ServerIP: net.IPv4(byte(netA), byte(netB), byte(oct3), byte(oct4+1)).To4(),
		ClientIP: net.IPv4(byte(netA), byte(netB), byte(oct3), byte(oct4+2)).To4(),
	}, nil
}

func ShuffledPool(start, end int) []int {
	vals := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		vals = append(vals, i)
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(vals), func(i, j int) { vals[i], vals[j] = vals[j], vals[i] })
	return vals
}

func CIDRToMaskAndNetwork(cidr string) (network net.IP, mask net.IPMask, prefix int, err error) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, 0, err
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil, nil, 0, fmt.Errorf("only IPv4 CIDR is supported for route command: %s", cidr)
	}
	return ip.To4().Mask(n.Mask), n.Mask, ones, nil
}

func MaskString(mask net.IPMask) string {
	if len(mask) == 4 {
		return net.IP(mask).String()
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

func IPv4TotalLength(buf []byte) (int, bool) {
	if len(buf) < 20 || buf[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl {
		return 0, false
	}
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if total < ihl || total > 65535 {
		return 0, false
	}
	return total, true
}

func IPv6PayloadTotalLength(buf []byte) (int, bool) {
	if len(buf) < 40 || buf[0]>>4 != 6 {
		return 0, false
	}
	payload := int(binary.BigEndian.Uint16(buf[4:6]))
	return 40 + payload, true
}
