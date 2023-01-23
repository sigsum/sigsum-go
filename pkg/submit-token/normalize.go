package token

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// Normalizes a utf8 domain name.
func NormalizeDomainName(domain string) (string, error) {
	n := norm.NFKC.String(domain) // Unicode normalization
	l := strings.ToLower(n)       // Unicode lowercase
	a, err := idna.ToASCII(l)     // A-label form (no-op for all-ascii labels)
	if err != nil {
		return "", fmt.Errorf("failed converting domain %q to a-label form: %v", l, err)
	}
	u, err := idna.ToUnicode(a)
	if err != nil {
		return "", fmt.Errorf("failed converting domain %q to u-label form: %v", a, err)
	}
	if !norm.NFKC.IsNormalString(u) {
		return "", fmt.Errorf("a-label domain %q was decoded to un-normalized unicode %q",
			a, u)
	}
	if strings.ToLower(u) != u {
		return "", fmt.Errorf("a-label domain %q was decoded to not all-lowercase unicode %q",
			a, u)
	}

	return u, nil
}
