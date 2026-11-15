//go:build !freebsd

package run

// DenyTracing is FreeBSD's: the companion ships for FreeBSD, and elsewhere
// (a development machine, CI) it runs as whoever starts it.
func DenyTracing() error { return nil }
