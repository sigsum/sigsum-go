package token

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	for _, table := range [][2]string{
		{"foo.com", "foo.com"},              // No-op
		{"foO.coM", "foo.com"},              // ASCII to lower
		{"räka.se", "räka.se"},              // No-op
		{"rÄKa.se", "räka.se"},              // Unicode to lower
		{"Ra\u0308ka.se", "räka.se"},        // Combining char
		{"\u212bngström.se", "ångström.se"}, // Compatibility char
	} {
		out, err := NormalizeDomainName(table[0])
		if err != nil {
			t.Fatalf("normalization failed on %q: %v", table[0], err)
		}
		if out != table[1] {
			t.Errorf("unexpected normalization of %q, got %q, wanted %q",
				table[0], out, table[1])
		}
	}
}

func TestNormalizeReject(t *testing.T) {
	for _, table := range [][2]string{
		{"xn--72g.com", "un-normalized unicode"}, // Compatibility char
	} {
		out, err := NormalizeDomainName(table[0])
		if err == nil {
			t.Errorf("accepted invalid domain %q, returned %q", table[0], out)
			continue
		}
		if !strings.Contains(err.Error(), table[1]) {
			t.Errorf("unexpected error type for %q, got %v, expected substring %q\n",
				table[0], err, table[1])
		}
	}
}
