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

// TODO: Also support named policies located in the regular file
// system. E.g., check the environment variable
// ${SIGSUM_POLICY_DIR}, falling back to /etc/sigsum/policy.
// Intention is to have a ByName function that looks in both places.
// See https://git.glasklar.is/sigsum/project/documentation/-/blob/main/proposals/2025-07-named-policies.md

// Files in /etc/sigsum/policy/ are expected to have the suffix
// ".sigsum-policy" -- we intentionally use a different suffix for builtin
// policy files since these are only used for embedding into the program,
// they should not be confused with /etc/sigsum/policy/ files.
const (
	builtinPolicyFilenameSuffix    = ".builtin-policy"
	installedPolicyFilenameSuffix  = ".sigsum-policy"
	defaultPolicyFileDirectory     = "/etc/sigsum/policy"
	policyFileDirectoryEnvVariable = "SIGSUM_POLICY_DIR"
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
	// Try first from file, then try builtin
	p, err1 := readFromPolicyDir(name)
	if err1 == nil {
		return p, nil
	}
	p, err2 := BuiltinByName(name)
	if err2 == nil {
		log.Info("Found builtin policy '%v'", name)
		return p, nil
	}
	err := fmt.Errorf("Failed to get named policy for name '%v', errors '%v' and '%v'", name, err1, err2)
	return nil, err
}

func readFromPolicyDir(name string) (*Policy, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	directory := os.Getenv(policyFileDirectoryEnvVariable)
	if len(directory) == 0 {
		directory = defaultPolicyFileDirectory
	}
	filePath := directory + "/" + name + installedPolicyFilenameSuffix
	p, err := ReadPolicyFile(filePath)
	if err == nil {
		log.Info("Successfully read policy from file %v", filePath)
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
