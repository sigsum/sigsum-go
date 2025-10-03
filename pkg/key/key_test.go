package key

import (
	"bytes"
	"testing"
)

func TestParsePublicKeysFile(t *testing.T) {
	for _, table := range []struct {
		desc, input string
		expCount    int // expCount > 0 means expected success
	}{
		{"empty", "", 0},
		{"comment only", "# no keys\n", 0},
		{"single-key",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
`, 1},
		{"two-keys",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, 2},
		{"two-keys-comments",
			`# a key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym key 1

# some empty lines
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn key 2

`, 2},
		{"line-with-garbage",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
xxx
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, 0},
		{"line-with-bad-comment",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
  # xxx
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, 0},
		{"duplicate-key",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym key 1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn key 2
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym same as key 1`, 0},
	} {
		buf := bytes.NewBufferString(table.input)
		keys, _, err := parsePublicKeysFile(buf, table.desc, false)
		got := len(keys)
		if table.expCount > 0 {
			if err != nil {
				t.Errorf("unexpected failure: %v", err)
			} else if got != table.expCount {
				t.Errorf("unexpected number of keys, got %d, want %d", got, table.expCount)
			}
		} else {
			if err == nil {
				t.Errorf("expected failure, but got %d keys", got)
			}
		}
	}
}

func TestParsePublicKeysFileWithPolicyNames(t *testing.T) {
	for _, table := range []struct {
		desc, input   string
		getPolicy     bool
		expCount      int // expCount > 0 means expected success
		expPolicyName string
	}{
		{"empty", "", true, 0, ""},
		{"comment only", "# no keys\n", true, 0, ""},
		{"single-key",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
`, true, 1, ""},
		{"single-key-with-policy",
			`sigsum-policy="mypolicy" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
`, true, 1, "mypolicy"},
		{"single-key-bad-policy",
			`sigsum-policy=mypolicy ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
`, true, 0, ""},
		{"two-keys",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, true, 2, ""},
		{"two-keys-with-same-policy",
			`sigsum-policy="abcd" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
sigsum-policy="abcd" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, true, 2, "abcd"},
		{"two-keys-with-different-policy",
			`sigsum-policy="abcd" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
sigsum-policy="other" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, true, 0, ""},
		{"two-keys-with-different-policy-but-dont-care",
			`sigsum-policy="abcd" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
sigsum-policy="other" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, false, 2, ""},
		{"two-keys-only-one-policy-1",
			`sigsum-policy="abcd" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, true, 0, ""},
		{"two-keys-only-one-policy-2",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
sigsum-policy="abcd" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, true, 0, ""},
		{"two-keys-only-one-policy-but-dont-care",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym
sigsum-policy="abcd" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn
`, false, 2, ""},
		{"two-keys-comments",
			`# a key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym key 1

# some empty lines
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn key 2

`, true, 2, ""},
		{"two-keys-comments-and-policy",
			`# a key
sigsum-policy="aaabbb" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym key 1

# some empty lines
sigsum-policy="aaabbb" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn key 2

`, true, 2, "aaabbb"},
		{"duplicate-key",
			`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym key 1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLyn key 2
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym same as key 1`, true, 0, ""},
	} {
		buf := bytes.NewBufferString(table.input)
		keys, policyName, err := parsePublicKeysFile(buf, table.desc, table.getPolicy)
		got := len(keys)
		if table.expCount > 0 {
			if err != nil {
				t.Errorf("unexpected failure: %v", err)
			} else if got != table.expCount {
				t.Errorf("unexpected number of keys, got %d, want %d", got, table.expCount)
			} else if policyName != table.expPolicyName {
				t.Errorf("unexpected policy name, got '%q', want '%q'", policyName, table.expPolicyName)
			}
		} else {
			if err == nil {
				t.Errorf("expected failure, but got %d keys", got)
			}
		}
	}
}
