// package submit acts as a sigsum submit client
// It submits a leaf to a log, and collects a sigsum proof.
package submit

import (
	"context"
	"fmt"
	"time"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	token "sigsum.org/sigsum-go/pkg/submit-token"
)

const (
	defaultPollDelay = 2 * time.Second
	defaultTimeout   = 30 * time.Second
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
	signature, err := signer.Sign(message[:])
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
	leaf, err := req.Verify()
	if err != nil {
		return proof.SigsumProof{}, fmt.Errorf("verifying leaf request failed: %v", err)
	}
	leafHash := leaf.ToHash()

	logs := config.Policy.GetLogsWithUrl()
	if len(logs) == 0 {
		return proof.SigsumProof{}, fmt.Errorf("no logs defined in policy")
	}
	for _, entity := range logs {
		var tokenHeader *string
		if config.RateLimitSigner != nil && len(config.Domain) > 0 {
			token, err := token.MakeToken(config.RateLimitSigner, &entity.PubKey)
			if err != nil {
				return proof.SigsumProof{}, fmt.Errorf("creating submit token failed: %v", err)
			}
			s := fmt.Sprintf("%s %x", config.Domain, token)
			tokenHeader = &s
		}

		client := client.New(client.Config{
			UserAgent: config.getUserAgent(),
			LogURL:    entity.Url,
		})

		logKeyHash := crypto.HashBytes(entity.PubKey[:])
		pr, err := func() (proof.SigsumProof, error) {
			ctx, cancel := context.WithTimeout(ctx, config.getTimeout())
			defer cancel()
			return submitLeafToLog(ctx, config.Policy, client, &logKeyHash, tokenHeader, config.sleep, req, &leafHash)
		}()
		if err == nil {
			pr.Leaf = proof.NewShortLeaf(&leaf)
			return pr, nil
		}
		log.Error("Submitting to log %q failed: %v", entity.Url, err)
	}
	return proof.SigsumProof{}, fmt.Errorf("all logs failed, giving up")
}

func submitLeafToLog(ctx context.Context, policy *policy.Policy,
	cli client.Log, logKeyHash *crypto.Hash, tokenHeader *string, sleep func(context.Context) error,
	req *requests.Leaf, leafHash *crypto.Hash) (proof.SigsumProof, error) {
	pr := proof.SigsumProof{
		// Note: Leaves to caller to populate proof.Leaf.
		LogKeyHash: *logKeyHash,
	}

	for {
		persisted, err := cli.AddLeaf(ctx, *req, tokenHeader)

		if err != nil {
			return proof.SigsumProof{}, err
		}
		if persisted {
			break
		}
		if err := sleep(ctx); err != nil {
			return proof.SigsumProof{}, err
		}
	}
	// Leaf submitted, now get a signed tree head + inclusion proof.
	for {
		var err error
		pr.TreeHead, err = cli.GetTreeHead(ctx)
		if err != nil {
			return proof.SigsumProof{}, err
		}
		if err := policy.VerifyCosignedTreeHead(&pr.LogKeyHash, &pr.TreeHead); err != nil {
			return proof.SigsumProof{}, fmt.Errorf("verifying tree head failed: %v", err)
		}

		// See if we can have an inclusion proof for this tree size.
		if pr.TreeHead.Size == 0 {
			// Certainly not included yet.
			if err := sleep(ctx); err != nil {
				return proof.SigsumProof{}, err
			}
			continue
		}
		// Special case for the very first leaf.
		if pr.TreeHead.Size == 1 {
			if pr.TreeHead.RootHash != *leafHash {
				// Certainly not included yet.
				if err := sleep(ctx); err != nil {
					return proof.SigsumProof{}, err
				}
				continue
			}
		} else {
			pr.Inclusion, err = cli.GetInclusionProof(ctx,
				requests.InclusionProof{
					Size:     pr.TreeHead.Size,
					LeafHash: *leafHash,
				})
			if err == client.HttpNotFound {
				log.Info("no inclusion proof yet, will retry")
				if err := sleep(ctx); err != nil {
					return proof.SigsumProof{}, err
				}
				continue
			}
			if err != nil {
				return proof.SigsumProof{}, fmt.Errorf("failed to get inclusion proof: %v", err)
			}
		}

		// Check validity.
		if err = pr.Inclusion.Verify(leafHash, &pr.TreeHead.TreeHead); err != nil {
			return proof.SigsumProof{}, fmt.Errorf("inclusion proof invalid: %v", err)
		}

		return pr, nil
	}
}
