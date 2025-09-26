package ssh

import (
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestParsePublicEd25519(t *testing.T) {
	expKey, err := crypto.PublicKeyFromHex("314cb82ac8b5fe90cf18bf190afa4759b80779709f991f736f044d5e13bcbca6")
	if err != nil {
		t.Fatalf("parsing test key failed: %v", err)
	}
	for _, table := range []struct {
		desc       string
		ascii      string
		expSuccess bool
	}{
		{"basic", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym", true},
		{"with newline", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym\n", true},
		{"with comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true},
		{"truncated b64", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLy comment", false},
		{"truncated bin", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4T comment", false},
	} {
		key, err := ParsePublicEd25519(table.ascii)
		if err != nil {
			if table.expSuccess {
				t.Errorf("%q: parsing failed: %v", table.desc, err)
			}
		} else {
			if !table.expSuccess {
				t.Errorf("%q: unexpected success, should have failed", table.desc)
			} else if key != expKey {
				t.Errorf("%q: parsing gave wrong key: %x", table.desc, key)
			}
		}
	}
}

func TestParsePublicEd25519WithPolicyName(t *testing.T) {
	expKey, err := crypto.PublicKeyFromHex("314cb82ac8b5fe90cf18bf190afa4759b80779709f991f736f044d5e13bcbca6")
	if err != nil {
		t.Fatalf("parsing test key failed: %v", err)
	}
	for _, table := range []struct {
		desc          string
		ascii         string
		expSuccess    bool
		expPolicyName string
	}{
		{"basic", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym", true, ""},
		{"with newline", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym\n", true, ""},
		{"with comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true, ""},
		{"truncated b64", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLy comment", false, ""},
		{"truncated bin", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4T comment", false, ""},
		{"with ok policy name simple", "sigsum-policy=\"abc\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true, "abc"},
		{"with ok policy name with minus sign", "sigsum-policy=\"abc-123\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true, "abc-123"},
		{"with bad policy name, missing end quote", "sigsum-policy=\"abc ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, missing start quote", "sigsum-policy=abc\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, missing quotes", "sigsum-policy=abc ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, only one quote", "sigsum-policy=\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, double equal signs", "sigsum-policy==\"abc\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, nothing after equal sign", "sigsum-policy= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, space in name", "sigsum-policy=\"aa bb\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, embedded quote", "sigsum-policy=\"aa\"bb\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, embedded and escaped quote", "sigsum-policy=\"aa\\\"bb\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with bad policy name, single quotes", "sigsum-policy='mypolicy' ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
		{"with ok policy name, embedded underscore", "sigsum-policy=\"aa_bb\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true, "aa_bb"},
		{"with ok policy name, embedded dollar sign", "sigsum-policy=\"aa$bb\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true, "aa$bb"},
		{"with policy name twice", "sigsum-policy=\"abc\" sigsum-policy=\"def\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", false, ""},
	} {
		key, policyName, err := ParsePublicEd25519WithPolicyName(table.ascii)
		if err != nil {
			if table.expSuccess {
				t.Errorf("%q: parsing failed: %v", table.desc, err)
			}
		} else {
			if !table.expSuccess {
				t.Errorf("%q: unexpected success, should have failed", table.desc)
			} else if key != expKey {
				t.Errorf("%q: parsing gave wrong key: %x", table.desc, key)
			} else if policyName != table.expPolicyName {
				t.Errorf("%q: parsing gave wrong policy name: '%q' != '%q'", table.desc, policyName, table.expPolicyName)
			}
		}
	}
}
