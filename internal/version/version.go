package version

import (
	"fmt"
	"runtime/debug"
)

func ModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	// When built, e.g., using go install .../sigsum-go@vX.Y.Z.
	version := info.Main.Version
	if version != "(devel)" {
		return version
	}

	// Use git commit, if available. The vcs.* fields are
	// populated when running "go build" in a git checkout,
	// *without* listing specific source files on the commandline.
	m := make(map[string]string)
	for _, setting := range info.Settings {
		m[setting.Key] = setting.Value
	}
	revision, ok := m["vcs.revision"]
	if !ok {
		return version
	}
	version = fmt.Sprintf("git %s", revision)
	if t, ok := m["vcs.time"]; ok {
		version += " " + t
	}
	// Note that any untracked file (if not listed in .gitignore)
	// counts as a local modification. Which makes sense, since
	// the go toolchain determines what to do automatically, based
	// on which files exist. For this flag to be reliable, avoid
	// adding patterns in .gitignore that could match files that
	// have meaning to the go toolchain.
	if m["vcs.modified"] != "false" {
		version += " (with local changes)"
	}

	return version
}

func DisplayVersion(tool string) {
	fmt.Printf("%s (sigsum-go module) %s\n", tool, ModuleVersion())
}
