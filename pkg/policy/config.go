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

// Represents a config file being parsed.
type config struct {
	policy *Policy
	names  map[string]Quorum
}

func (c *config) ifdef(name string) bool {
	_, ok := c.names[name]
	return ok
}

func (c *config) parseLog(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("invalid log policy line, public key required, url optional")
	}
	key, err := crypto.PublicKeyFromHex(args[0])
	if err != nil {
		return err
	}
	var url string
	if len(args) > 1 {
		url = args[1]
	}
	_, err = c.policy.addLog(&Entity{PublicKey: key, URL: url})
	return err
}

func (c *config) parseWitness(args []string) error {
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("invalid witness policy line, public key and name required, url optional")
	}
	name := args[0]
	key, err := crypto.PublicKeyFromHex(args[1])
	if err != nil {
		return err
	}
	if c.ifdef(name) {
		return fmt.Errorf("duplicate name: %q", name)
	}
	var url string
	if len(args) > 2 {
		url = args[2]
	}
	h, err := c.policy.addWitness(&Entity{PublicKey: key, URL: url})
	if err != nil {
		return err
	}
	c.names[name] = &quorumSingle{h}
	return nil
}

func (c *config) parseGroup(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("too few arguments, name, threshold and at least one member is required")
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
		threshold, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if threshold < 1 || threshold > n {
			return fmt.Errorf("threshold out of range")
		}
	}
	if c.ifdef(name) {
		return fmt.Errorf("duplicate name %q", name)
	}

	subQuorums := []Quorum{}
	// TODO: Warn or fail if there's overlap between group members?
	for _, member := range args[2:] {
		if q, ok := c.names[member]; ok {
			subQuorums = append(subQuorums, q)
		} else {
			return fmt.Errorf("undefined name: %q", member)
		}
	}
	if len(subQuorums) != n {
		panic("internal error")
	}
	c.names[name] = &quorumKofN{subQuorums: subQuorums, k: threshold}
	return nil
}

func (c *config) parseQuorum(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("incorrect number of arguments: group or witness required")
	}
	if c.policy.quorum != nil {
		return fmt.Errorf("quorum can only be set once")
	}

	name := args[0]
	if q, ok := c.names[name]; ok {
		c.policy.quorum = q
	} else {
		return fmt.Errorf("undefined name %q", name)
	}
	return nil
}

func (c *config) parseLine(fields []string) (err error) {
	keyword, args := fields[0], fields[1:]
	switch keyword {
	case "log":
		err = c.parseLog(args)
	case "witness":
		err = c.parseWitness(args)
	case "group":
		err = c.parseGroup(args)
	case "quorum":
		err = c.parseQuorum(args)
	default:
		err = fmt.Errorf("unknown keyword: %q", keyword)
	}
	return
}

func ParseConfig(file io.Reader) (*Policy, error) {
	config := config{
		policy: newEmptyPolicy(),
		names:  map[string]Quorum{ConfigNone: &quorumKofN{}},
	}

	lineno := 0
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		lineno++
		line := scanner.Text()
		if comment := strings.Index(line, "#"); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if err := config.parseLine(fields); err != nil {
			return nil, fmt.Errorf("%d: %v", lineno, err)
		}
	}
	if config.policy.quorum == nil {
		return nil, fmt.Errorf("no quorum defined")
	}
	return config.policy, nil
}

func ReadPolicyFile(name string) (*Policy, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseConfig(f)
}
