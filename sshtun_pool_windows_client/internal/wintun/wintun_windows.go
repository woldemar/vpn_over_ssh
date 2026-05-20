//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type Adapter struct {
	Name string

	mu     sync.Mutex
	dev    wgtun.Device
	bufs   [][]byte
	sizes  []int
	queued [][]byte
	closed bool
}

func CreateOrOpen(name string) (*Adapter, error) {
	dev, err := wgtun.CreateTUN(name, 0)
	if err != nil {
		return nil, fmt.Errorf("create/open Wintun adapter via wireguard/tun: %w", err)
	}
	actualName, err := dev.Name()
	if err != nil || actualName == "" {
		actualName = name
	}
	return &Adapter{Name: actualName, dev: dev}, nil
}

func (a *Adapter) StartSession(capacity uint32) error {
	// wireguard/tun owns the Wintun session lifecycle internally. Kept as a
	// no-op for compatibility with the previous raw-DLL wrapper.
	if a == nil || a.dev == nil {
		return errors.New("wintun adapter is not created")
	}
	return nil
}

func (a *Adapter) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	dev := a.dev
	a.dev = nil
	a.queued = nil
	a.mu.Unlock()
	if dev != nil {
		_ = dev.Close()
	}
}

func (a *Adapter) Delete() error {
	a.Close()
	return nil
}

func (a *Adapter) ensureBatchLocked() {
	if len(a.bufs) > 0 {
		return
	}
	batch := 1
	if a.dev != nil {
		if n := a.dev.BatchSize(); n > batch {
			batch = n
		}
	}
	a.bufs = make([][]byte, batch)
	a.sizes = make([]int, batch)
	for i := range a.bufs {
		a.bufs[i] = make([]byte, 65535)
	}
}

func (a *Adapter) ReadPacket() ([]byte, error) {
	for {
		a.mu.Lock()
		if a.closed || a.dev == nil {
			a.mu.Unlock()
			return nil, errors.New("wintun adapter is closed")
		}
		if len(a.queued) > 0 {
			pkt := a.queued[0]
			copy(a.queued, a.queued[1:])
			a.queued[len(a.queued)-1] = nil
			a.queued = a.queued[:len(a.queued)-1]
			a.mu.Unlock()
			return pkt, nil
		}
		a.ensureBatchLocked()
		dev := a.dev
		bufs := a.bufs
		sizes := a.sizes
		a.mu.Unlock()

		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			continue
		}

		packets := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 {
				continue
			}
			pkt := make([]byte, sizes[i])
			copy(pkt, bufs[i][:sizes[i]])
			packets = append(packets, pkt)
		}
		if len(packets) == 0 {
			continue
		}
		if len(packets) == 1 {
			return packets[0], nil
		}
		a.mu.Lock()
		if !a.closed {
			a.queued = append(a.queued, packets[1:]...)
		}
		a.mu.Unlock()
		return packets[0], nil
	}
}

func (a *Adapter) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	a.mu.Lock()
	dev := a.dev
	closed := a.closed
	a.mu.Unlock()
	if closed || dev == nil {
		return errors.New("wintun adapter is closed")
	}
	_, err := dev.Write([][]byte{pkt}, 0)
	return err
}
