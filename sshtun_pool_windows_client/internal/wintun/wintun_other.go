//go:build !windows

package wintun

import "fmt"

type Adapter struct{ Name string }

func CreateOrOpen(name string) (*Adapter, error)      { return nil, fmt.Errorf("windows-only client") }
func (a *Adapter) StartSession(capacity uint32) error { return fmt.Errorf("windows-only client") }
func (a *Adapter) Close()                             {}
func (a *Adapter) Delete() error                      { return nil }
func (a *Adapter) ReadPacket() ([]byte, error)        { return nil, fmt.Errorf("windows-only client") }
func (a *Adapter) WritePacket(pkt []byte) error       { return fmt.Errorf("windows-only client") }
