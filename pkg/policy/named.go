package policy

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// Reject names involving directories
	if strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("invalid policy name %q, must not contain %v", name, filepath.Separator)
	}
	return nil
}

// This function returns either the policy or, if raw is true, the corresponding file contents
func byName(name string, raw bool) (*Policy, []byte, error) {
	if err := checkName(name); err != nil {
		return nil, nil, err
	}
	// If there is a file for this policy in the policy directory
	// then that should be used. If no such file is found, then a
	// builtin policy should be used.
	p, data, err1 := readFromPolicyDir(name, raw)
	if err1 == nil {
		return p, data, nil
	}
	p, data, err2 := builtinByName(name, raw)
	if err2 == nil {
		log.Info("Found builtin policy '%q'", name)
		return p, data, nil
	}
	err := fmt.Errorf("failed to get named policy for name '%q', errors '%v' and '%v'", name, err1, err2)
	return nil, nil, err
}

func ByName(name string) (*Policy, error) {
	p, _, err := byName(name, false)
	return p, err
}

func RawByName(name string) ([]byte, error) {
	_, data, err := byName(name, true)
	return data, err
}

// This function returns either the policy or, if raw is true, the corresponding file contents
func readFromPolicyDir(name string, raw bool) (*Policy, []byte, error) {
	if err := checkName(name); err != nil {
		return nil, nil, err
	}
	directory := os.Getenv(policyDirectoryEnvVariable)
	if len(directory) == 0 {
		directory = defaultPolicyDirectory
	}
	filePath := directory + "/" + name + installedPolicyFilenameSuffix
	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if raw {
		fileContents, err := io.ReadAll(f)
		return nil, fileContents, err
	}
	policy, err := ParseConfig(f)
	return policy, nil, err
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
		if e.Type().IsRegular() {
			if name, found := strings.CutSuffix(e.Name(), installedPolicyFilenameSuffix); found {
				names = append(names, name)
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

// This function returns either the policy or, if raw is true, the corresponding file contents
func builtinByName(name string, raw bool) (*Policy, []byte, error) {
	if err := checkName(name); err != nil {
		return nil, nil, err
	}
	f, err := builtin.Open(filepath.Join("builtin", name) + builtinPolicyFilenameSuffix)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if raw {
		fileContents, err := io.ReadAll(f)
		return nil, fileContents, err
	}
	policy, err := ParseConfig(f)
	return policy, nil, err
}

func BuiltinByName(name string) (*Policy, error) {
	p, _, err := builtinByName(name, false)
	return p, err
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

func BuiltinRead(name string) ([]byte, error) {
	_, data, err := builtinByName(name, true)
	return data, err
}
