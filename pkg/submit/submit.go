// package submit acts as a sigsum submit client
// It submits a leaf to a log, and collects a sigsum proof.
package submit

import (
	"context"
	"time"

//	"sigsum.org/sigsum-go/pkg/api"
//	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
//	token "sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
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
	// proof.
	PollDelay time.Duration

	UserAgent string

	// The policy specifies the logs and witnesses to use.
	Policy *policy.Policy

	// HTTPClient specifies the HTTP client to use when making requests to the log.
	// If nil, a default client is created.
	HTTPClient *http.Client
}

func (c *Config) getPollDelay() time.Duration {
	if c.PollDelay <= 0 {
		return defaultPollDelay
	}
	return c.PollDelay
}

func (c *Config) getTimeout() time.Duration {
	if c.PerLogTimeout <= 0 {
		return defaultTimeout
	}
	return c.PerLogTimeout
}

func (c *Config) getUserAgent() string {
	if len(c.UserAgent) == 0 {
		return defaultUserAgent
	}
	return c.UserAgent
}

// Sleep for the given delay, but fail early if the context is
// cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Config) sleep(ctx context.Context) error {
	return sleepWithContext(ctx, c.getPollDelay())
}


func SubmitMessage(ctx context.Context, config *Config, signer crypto.Signer, message *crypto.Hash) (proof.SigsumProof, error) {
	signature, err := types.SignLeafMessage(signer, message[:])
	if err != nil {
		return proof.SigsumProof{}, err
	}
	return SubmitLeafRequest(ctx, config, &requests.Leaf{
		Message:   *message,
		Signature: signature,
		PublicKey: signer.Public(),
	})
}

func SubmitLeafRequest(ctx context.Context, config *Config, req *requests.Leaf) (proof.SigsumProof, error) {
	log.Debug("Creating batch");
	b, err := NewBatch(ctx, config)	
	if err != nil {
		return proof.SigsumProof{}, err
	}
	defer b.Close()
	var pr proof.SigsumProof
	log.Debug("Submitting request");
	if err := b.SubmitLeafRequest(req, func(res proof.SigsumProof) { pr = res }); err != nil {
		return proof.SigsumProof{}, err
	}
	log.Debug("Waiting")
	if err := b.Close(); err != nil {
		return proof.SigsumProof{}, err
	}
	return pr, nil
}
