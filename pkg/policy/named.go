package policy

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sigsum.org/sigsum-go/pkg/log"
	"slices"
	"strings"
)

// See https://git.glasklar.is/sigsum/project/documentation/-/blob/main/proposals/2025-07-named-policies.md

// Files in /etc/sigsum/policy/ are expected to have the suffix
// ".sigsum-policy" -- we intentionally use a different suffix for builtin
// policy files since these are only used for embedding into the program,
// they should not be confused with /etc/sigsum/policy/ files.
const (
	builtinPolicyFilenameSuffix   = ".builtin-policy"
	installedPolicyFilenameSuffix = ".sigsum-policy"
	defaultPolicyDirectory        = "/etc/sigsum/policy"
	policyDirectoryEnvVariable    = "SIGSUM_POLICY_DIR"
)

//go:embed "builtin/*.builtin-policy"
var builtin embed.FS

func checkName(name string) error {
	// Reject names that do not match regexp (see named policy proposal)
	const expr = "^[a-z0-9][a-z0-9-]+$"
	re := regexp.MustCompile(expr)
	if !re.MatchString(name) {
		return fmt.Errorf("invalid policy name %q, does not match regexp %q", name, expr)
	}
	return nil
}

func openByName(name string) (io.ReadCloser, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	// If there is a file for this policy in the policy directory
	// then that should be used. If no such file is found, then a
	// builtin policy should be used.
	f, err1 := openFromPolicyDir(name)
	if err1 == nil {
		return f, nil
	}
	f, err2 := openBuiltinByName(name)
	if err2 == nil {
		log.Info("Found builtin policy '%q'", name)
		return f, nil
	}
	err := fmt.Errorf("failed to get named policy for name '%q', errors '%v' and '%v'", name, err1, err2)
	return nil, err
}

func ByName(name string) (*Policy, error) {
	f, err := openByName(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseConfig(f)
}

func ReadByName(name string) ([]byte, error) {
	f, err := openByName(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func openFromPolicyDir(name string) (io.ReadCloser, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	directory := os.Getenv(policyDirectoryEnvVariable)
	if len(directory) == 0 {
		directory = defaultPolicyDirectory
	}
	filePath := directory + "/" + name + installedPolicyFilenameSuffix
	return os.Open(filePath)
}

func listFromPolicyDir() []string {
	directory := os.Getenv(policyDirectoryEnvVariable)
	if len(directory) == 0 {
		directory = defaultPolicyDirectory
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		// Using Stat below because we want to allow symlinks but
		// require that a symlink resolves to a regular file
		filePath := directory + "/" + e.Name()
		if fileInfo, err := os.Stat(filePath); err == nil && fileInfo.Mode().IsRegular() {
			if name, found := strings.CutSuffix(e.Name(), installedPolicyFilenameSuffix); found {
				if err := checkName(name); err == nil {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

func List() []string {
	builtin := BuiltinList()
	installed := listFromPolicyDir()
	all := append(builtin, installed...)
	// Use Sort() and Compact() to remove duplicates
	slices.Sort(all)
	all = slices.Compact(all)
	return all
}

func openBuiltinByName(name string) (io.ReadCloser, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	return builtin.Open(filepath.Join("builtin", name) + builtinPolicyFilenameSuffix)
}

func BuiltinByName(name string) (*Policy, error) {
	f, err := openBuiltinByName(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseConfig(f)
}

func BuiltinList() []string {
	entries, err := builtin.ReadDir("builtin")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			if name, found := strings.CutSuffix(e.Name(), builtinPolicyFilenameSuffix); found {
				names = append(names, name)
			}
		}
	}
	return names
}

func ReadBuiltinByName(name string) ([]byte, error) {
	f, err := openBuiltinByName(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
