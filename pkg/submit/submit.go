// package submit acts as a sigsum submit client
// It submits one or more leaf to the logs specified by policy, and
// collects corresponding sigsum proofs.
package submit

import (
	"time"

	"net/http"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
)

const (
	defaultPollDelay = 2 * time.Second
	// Default log server publishing interval is 30 seconds, so
	// use something longer.
	defaultTimeout   = 45 * time.Second
	defaultUserAgent = "sigsum-go submit"
)

type Config struct {
	// Domain and signer to use for rate limit sigsum-token: header.
	Domain          string
	RateLimitSigner crypto.Signer

	// Timeout, before trying try next log. Zero implies a default
	// timeout is used.
	PerLogTimeout time.Duration

	// Delay when repeating add-leaf requests to the log, as well
	// as for polling for a cosigned tree head and inclusion
	// proof. Zero implies a default timeout is used.
	PollDelay time.Duration

	// HTTP user agent, empty implies a default user agent string.
	UserAgent string

	// The policy specifies the logs and witnesses to use.
	Policy *policy.Policy

	// HTTPClient specifies the HTTP client to use when making requests to the log.
	// If nil, a default client is created.
	HTTPClient *http.Client
}

func (c *Config) withDefaults() Config {
	res := *c

	if c.PollDelay <= 0 {
		res.PollDelay = defaultPollDelay
	}
	if c.PerLogTimeout <= 0 {
		res.PerLogTimeout = defaultTimeout
	}
	if c.UserAgent == "" {
		res.UserAgent = defaultUserAgent
	}
	return res
}
