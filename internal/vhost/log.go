package vhost

import (
	"uml-container/internal/log"
)

// pkgLog is the default logger for the vhost subsystem. Every Server and
// VirtQueue shares it unless overridden via SetLogger (e.g. to capture output
// in tests or to silence the subsystem). Defaults to the process logger at
// whatever level the process configured (Info by default; Debug if the CLI
// passed -debug).
var pkgLog = log.Default().WithPrefix("[vhost]")

// SetLogger replaces the package-wide logger used by Server, VirtQueue, and
// NetDevice. Pass nil to restore the process default. It is safe to call at
// any time; the change is visible to subsequently started processors.
func SetLogger(l *log.Logger) {
	if l == nil {
		pkgLog = log.Default().WithPrefix("[vhost]")
		return
	}
	pkgLog = l.WithPrefix("[vhost]")
}
