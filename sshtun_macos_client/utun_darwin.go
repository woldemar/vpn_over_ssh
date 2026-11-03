//go:build darwin

package main

// Прямая работа с utun macOS через сисколлы (без внешних VPN-библиотек):
// PF_SYSTEM/SYSPROTO_CONTROL + com.apple.net.utun_control. Фреймы utun имеют
// 4-байтовый заголовок адресного семейства перед IP-пакетом — здесь он
// снимается/добавляется.

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	utunControlName  = "com.apple.net.utun_control"
	utunOptIfName    = 2  // UTUN_OPT_IFNAME
	sysProtoControl  = 2  // SYSPROTO_CONTROL (не сгенерирован в x/sys/unix)
	afSystem         = 32 // AF_SYSTEM
	// CTLIOCGINFO: _IOWR('N', 3, struct ctl_info)
	ctlIOCInfo = (0x40000000 | 0x1000000) | ('N' << 8) | 3
)

type utunDevice struct {
	fd   int
	name string
	buf  []byte
}

// createUtun открывает utun, предпочитая юниты 4..15 (0..3 обычно заняты
// системой). Возвращает устройство и его имя (utunN).
func createUtun() (*utunDevice, error) {
	fd, err := unix.Socket(afSystem, unix.SOCK_DGRAM, sysProtoControl)
	if err != nil {
		return nil, fmt.Errorf("socket(PF_SYSTEM): %w", err)
	}
	var ctlInfo unix.CtlInfo
	copy(ctlInfo.Name[:], utunControlName)
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(sysProtoControl),
		uintptr(ctlIOCInfo),
		uintptr(unsafe.Pointer(&ctlInfo)),
		0, 0,
	)
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("CTLIOCGINFO %q: %v", utunControlName, errno)
	}

	units := []uint32{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	for _, id := range units {
		sa := &unix.SockaddrCtl{ID: ctlInfo.Id, Unit: id}
		if err := unix.Connect(fd, sa); err != nil {
			continue // юнит занят — пробуем следующий
		}
		nameRaw, err := unix.GetsockoptString(fd, sysProtoControl, utunOptIfName)
		if err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("UTUN_OPT_IFNAME: %w", err)
		}
		name := strings.TrimRight(nameRaw, "\x00")
		return &utunDevice{fd: fd, name: name, buf: make([]byte, 4+maxPacket)}, nil
	}
	_ = unix.Close(fd)
	return nil, fmt.Errorf("нет свободного utun (юниты 4..15 заняты)")
}

func (u *utunDevice) Name() string { return u.name }

// Read читает один IP-пакет (4-байтовый заголовок семейства снимаем).
func (u *utunDevice) Read() ([]byte, error) {
	n, err := unix.Read(u.fd, u.buf)
	if err != nil {
		return nil, err
	}
	if n <= 4 {
		return nil, nil
	}
	pkt := make([]byte, n-4)
	copy(pkt, u.buf[4:n])
	return pkt, nil
}

// Write отправляет один IP-пакет (добавляем 4-байтовый заголовок семейства).
func (u *utunDevice) Write(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	var af uint32
	switch pkt[0] >> 4 {
	case 4:
		af = 2 // Darwin AF_INET
	case 6:
		af = 30 // Darwin AF_INET6
	default:
		return fmt.Errorf("not an IP packet: first byte 0x%02x", pkt[0])
	}
	frame := make([]byte, 4+len(pkt))
	frame[3] = byte(af) // little-endian в заголовке utun
	copy(frame[4:], pkt)
	_, err := unix.Write(u.fd, frame)
	return err
}

func (u *utunDevice) Close() error { return unix.Close(u.fd) }
