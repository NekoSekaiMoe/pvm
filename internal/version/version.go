// Package version carries build metadata injected via -ldflags at build time
// (see deploy/Makefile / CI). GET /version and the envd version service both
// surface these values.
package version

import "runtime"

// These are set at link time:
//
//	go build -ldflags "-X uml-container/internal/version.Version=v1.2.3 -X uml-container/internal/version.Commit=abc1234"
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Info is the JSON shape returned by GET /version.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date,omitempty"`
	Goos    string `json:"goos"`
	Goarch  string `json:"goarch"`
}

// Current returns the current build info.
func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date, Goos: runtime.GOOS, Goarch: runtime.GOARCH}
}
