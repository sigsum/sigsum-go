package policy

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sigsum.org/sigsum-go/pkg/log"
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

func ByName(name string) (*Policy, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	// If there is a file for this policy in the policy directory
	// then that should be used. If no such file is found, then a
	// builtin policy should be used.
	p, err1 := readFromPolicyDir(name)
	if err1 == nil {
		return p, nil
	}
	p, err2 := BuiltinByName(name)
	if err2 == nil {
		log.Info("Found builtin policy '%q'", name)
		return p, nil
	}
	err := fmt.Errorf("failed to get named policy for name '%q', errors '%v' and '%v'", name, err1, err2)
	return nil, err
}

func readFromPolicyDir(name string) (*Policy, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	directory := os.Getenv(policyDirectoryEnvVariable)
	if len(directory) == 0 {
		directory = defaultPolicyDirectory
	}
	filePath := directory + "/" + name + installedPolicyFilenameSuffix
	p, err := ReadPolicyFile(filePath)
	if err == nil {
		log.Info("Successfully read policy from file %q", filePath)
	}
	return p, err
}

func BuiltinByName(name string) (*Policy, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	f, err := builtin.Open(filepath.Join("builtin", name) + builtinPolicyFilenameSuffix)
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

func BuiltinRead(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	f, err := builtin.Open(filepath.Join("builtin", name) + builtinPolicyFilenameSuffix)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
