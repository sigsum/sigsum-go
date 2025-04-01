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
// ${SIGSUM_POLICIES_DIR}, falling back to /etc/sigsum/policies. It's
// probably convenient to use the same name space for builtin policies
// and policy files, but we may then need a way to inhibit one or the
// other during lookup.
// Intention is to have a ByName function that looks in both places.

//go:embed "builtin/*.policy"
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
	f, err := builtin.Open(filepath.Join("builtin", name) + ".policy")
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
			if name, found := strings.CutSuffix(e.Name(), ".policy"); found {
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
	f, err := builtin.Open(filepath.Join("builtin", name) + ".policy")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
