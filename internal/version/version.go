// Package version holds the ZoneLint version string.
package version

import (
	"fmt"
	"runtime/debug"
)

// Version, Commit and Date are set at build time via -ldflags. When ZoneLint
// runs from a checkout without these flags, the values fall back to the build
// information recorded by the Go toolchain.
var (
	Version = "0.1.0"
	Commit  string
	Date    string
)

func init() {
	if Info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range Info.Settings {
			switch s.Key {
			case "vcs.tag":
				if Version == "0.1.0" || Version == "" {
					Version = s.Value
				}
			case "vcs.commit":
				if Commit == "" {
					Commit = s.Value
				}
			case "vcs.time":
				if Date == "" {
					Date = s.Value
				}
			}
		}
	}
}

// VersionString returns the human-readable version for --version output.
func VersionString() string {
	v := Version
	if v == "" {
		v = "0.1.0"
	}
	if Commit != "" {
		return fmt.Sprintf("%s (%s)", v, Commit[:min(12, len(Commit))])
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
