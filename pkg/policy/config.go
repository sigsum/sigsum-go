package policy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// Config file syntax is
//   log <pubkey> [<url>]
//   witness <name> <pubkey> [<url>]
//   group <name> <threshold> <name>...
//   quorum <name>
// with # used for comments.

const (
	// Predefined name representing an empty group. Using "quorum
	// none" defines a policy that doesn't require any cosignatures.
	ConfigNone = "none"
)

func parseLog(args []string) (Setting, error) {
	if len(args) < 1 || len(args) > 2 {
		return nil, fmt.Errorf("invalid log policy line, public key required, url optional")
	}
	key, err := crypto.PublicKeyFromHex(args[0])
	if err != nil {
		return nil, err
	}
	var url string
	if len(args) > 1 {
		url = args[1]
	}
	return AddLog(&Entity{PublicKey: key, URL: url}), nil
}

func parseWitness(args []string) (Setting, error) {
	if len(args) < 2 || len(args) > 3 {
		return nil, fmt.Errorf("invalid witness policy line, public key and name required, url optional")
	}
	name := args[0]
	key, err := crypto.PublicKeyFromHex(args[1])
	if err != nil {
		return nil, err
	}
	var url string
	if len(args) > 2 {
		url = args[2]
	}
	return AddWitness(name, &Entity{PublicKey: key, URL: url}), nil
}

func parseGroup(args []string) (Setting, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("too few arguments, name, threshold and at least one member is required")
	}
	n := len(args) - 2
	name := args[0]

	var threshold int
	switch s := string(args[1]); s {
	case "any":
		threshold = 1
	case "all":
		threshold = n
	default:
		var err error
		threshold, err = strconv.Atoi(s)
		if err != nil {
			return nil, err
		}
	}
	if threshold < 1 || threshold > n {
		return nil, fmt.Errorf("threshold out of range")
	}

	return AddGroup(name, threshold, args[2:]), nil
}

func parseQuorum(args []string) (Setting, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("incorrect number of arguments: group or witness required")
	}
	return SetQuorum(args[0]), nil
}

func parseLine(fields []string) (Setting, error) {
	keyword, args := fields[0], fields[1:]
	switch keyword {
	case "log":
		return parseLog(args)
	case "witness":
		return parseWitness(args)
	case "group":
		return parseGroup(args)
	case "quorum":
		return parseQuorum(args)
	default:
		return nil, fmt.Errorf("unknown keyword: %q", keyword)
	}
}

func isSpace(c rune) bool {
	return c == ' ' || c == '\t'
}

func checkLine(line string) error {
	// Note that IndexFunc attempts to decode utf8, and produces a
	// single replacement character (0xfffd) for each byte if it
	// encounters invalid utf8.
	invalidIndex := strings.IndexFunc(line, func(c rune) bool {
		valid := (c >= 0x80 || c == '\t' || (c >= 0x20 && c < 0x7F))
		return !valid
	})
	if invalidIndex >= 0 {
		return fmt.Errorf("invalid control character 0x%02x", line[invalidIndex])
	}
	return nil
}

func ParseConfig(file io.Reader) (*Policy, error) {
	b := newBuilder()
	lineno := 0
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		lineno++
		line := scanner.Text()
		if err := checkLine(line); err != nil {
			return nil, err
		}
		fields := strings.FieldsFunc(line, isSpace)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		setting, err := parseLine(fields)
		if err != nil {
			return nil, fmt.Errorf("%d: %v", lineno, err)
		}
		if err := setting.apply(b); err != nil {
			return nil, fmt.Errorf("%d: %v", lineno, err)
		}
	}
	return b.finish()
}

func ReadPolicyFile(name string) (*Policy, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	policy, err := ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy file %q: %v", name, err)
	}
	return policy, nil
}
