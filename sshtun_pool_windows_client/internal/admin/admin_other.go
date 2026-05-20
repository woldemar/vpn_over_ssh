//go:build !windows

package admin

import "fmt"

func IsAdmin() bool       { return false }
func RequireAdmin() error { return fmt.Errorf("windows-only client") }
