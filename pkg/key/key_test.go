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
		keys, err := parsePublicKeysFile(buf, table.desc)
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
