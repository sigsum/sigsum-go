package policy

import (
	"embed"
	"fmt"
	"io"
	"path/filepath"
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
const builtinPolicyFilenameSuffix string = ".builtin-policy"

//go:embed "builtin/*.builtin-policy"
var builtin embed.FS

func checkName(name string) error {
	// Reject names involving directories
	if strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("invalid policy name %q, must not contain %v", name, filepath.Separator)
	}
	return nil
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
