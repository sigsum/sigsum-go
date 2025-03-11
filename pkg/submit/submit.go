// package submit acts as a sigsum submit client It submits a leaf to a log, and
// collects a sigsum proof.
package submit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	token "sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	DefaultTimeout = 10 * time.Minute

	defaultPollDelay      = 2 * time.Second
	defaultRequestTimeout = 30 * time.Second
	defaultUserAgent      = "sigsum-go submit"
)

type Config struct {
	// Domain and signer to use for rate limit sigsum-token: header.
	Domain          string
	RateLimitSigner crypto.Signer

	// Timeout is the time before giving up on all submissions.  Zero implies a
	// default timeout is used.
	Timeout time.Duration

	// RequestTimeout is the time before giving up on a particular request,
	// e.g., adding a leaf or collecting its proof.  Zero implies a default
	// timeout is used.
	RequestTimeout time.Duration

	// Delay when repeating add-leaf requests to the log, as well as for polling
	// for a cosigned tree head and inclusion proof.
	PollDelay time.Duration

	UserAgent string

	// The policy specifies the logs and witnesses to use.
	Policy *policy.Policy

	// HTTPClient specifies the HTTP client to use when making requests to the
	// log.  If nil, a default client is created.
	HTTPClient *http.Client
}

func (c *Config) getPollDelay() time.Duration {
	if c.PollDelay <= 0 {
		return defaultPollDelay
	}
	return c.PollDelay
}

func (c *Config) getGlobalTimeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

func (c *Config) getRequestTimeout() time.Duration {
	if c.RequestTimeout <= 0 {
		return defaultRequestTimeout
	}
	return c.RequestTimeout
}

func (c *Config) getUserAgent() string {
	if len(c.UserAgent) == 0 {
		return defaultUserAgent
	}
	return c.UserAgent
}

// Sleep for the given delay, but fail early if the context is cancelled.
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
	proofs, err := SubmitLeafRequests(ctx, config, []requests.Leaf{requests.Leaf{
		Message:   *message,
		Signature: signature,
		PublicKey: signer.Public(),
	}})
	if err != nil {
		return proof.SigsumProof{}, err
	}
	return proofs[0], nil
}

// SubmitLeafRequests ensures that the given requests are logged in any log with
// sufficient amounts of witnessing (based on config.Policy).  The collected
// proofs of logging are returned in the same order as the input requests.
func SubmitLeafRequests(ctx context.Context, config *Config, reqs []requests.Leaf) ([]proof.SigsumProof, error) {
	logs, err := logClientsFromConfig(config)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithTimeout(ctx, config.getGlobalTimeout())
	defer cancel()
	submissions, err := submitLeaves(sctx, config.getRequestTimeout(), logs, reqs)
	if err != nil {
		return nil, err
	}
	return collectProofs(sctx, config.getRequestTimeout(), config.sleep, config.Policy, submissions)
}

type pendingSubmission struct {
	log       *logClient      // which log
	request   requests.Leaf   // which request
	leafHash  crypto.Hash     // expected leaf hash
	shortLeaf proof.ShortLeaf // leaf without checksum
}

type logClient struct {
	entity policy.Entity
	client api.Log
	header *token.SubmitHeader
}

func logClientsFromConfig(config *Config) ([]logClient, error) {
	var logs []logClient
	for _, entity := range config.Policy.GetLogsWithUrl() {
		var header *token.SubmitHeader
		if config.RateLimitSigner != nil && len(config.Domain) > 0 {
			signature, err := token.MakeToken(config.RateLimitSigner, &entity.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("creating submit token failed: %v", err)
			}
			header = &token.SubmitHeader{Domain: config.Domain, Token: signature}
		}
		client := client.New(client.Config{
			UserAgent:  config.getUserAgent(),
			URL:        entity.URL,
			HTTPClient: config.HTTPClient,
		})
		logs = append(logs, logClient{entity, client, header})
	}
	if len(logs) == 0 {
		return nil, fmt.Errorf("no logs defined in policy")
	}
	return logs, nil
}

// submitLeaves ensures we get HTTP status 2XX for each of the signed checksums.
// Use collectProofs() to ensure these 2XX responses transition into 200 OK with
// appropriate proofs of logging.
//
// Note: by ensuring that some log says it will take each signed checksum and
// then collecting the proofs, we don't wait as much for tree heads to rotate.
func submitLeaves(ctx context.Context, timeout time.Duration, logs []logClient, reqs []requests.Leaf) ([]pendingSubmission, error) {
	var submissions []pendingSubmission
	for i, req := range reqs {
		leaf, err := req.Verify()
		if err != nil {
			return nil, fmt.Errorf("verifying leaf request failed: %v", err)
		}

		for _, lc := range logs {
			if err = ctx.Err(); err != nil {
				return nil, err
			}

			log.Info("Attempting to submit checksum#%d to log: %s", i+1, lc.entity.URL)
			if err = submitLeaf(ctx, timeout, lc, req); err != nil {
				log.Error("Submitting to log %q failed: %v", lc.entity.URL, err)
				continue
			}

			submissions = append(submissions, pendingSubmission{
				log:       &lc,
				request:   req,
				leafHash:  leaf.ToHash(),
				shortLeaf: proof.NewShortLeaf(&leaf),
			})
			break
		}
		if err != nil {
			return nil, fmt.Errorf("all logs failed, giving up")
		}
	}
	return submissions, nil
}

func submitLeaf(ctx context.Context, timeout time.Duration, lc logClient, req requests.Leaf) error {
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := lc.client.AddLeaf(sctx, req, lc.header)
	return err // nil on HTTP status 2XX responses
}

// collectProofs ensures the pending submissions transition from HTTP status 2XX
// to HTTP status 200 OK in the respective logs. Proofs are then collected.
func collectProofs(ctx context.Context, timeout time.Duration, sleep func(ctx context.Context) error, policy *policy.Policy, submissions []pendingSubmission) ([]proof.SigsumProof, error) {
	var proofs []proof.SigsumProof
	for i, submission := range submissions {
		for {
			log.Info("Attempting to retrieve proof for checksum#%d", i+1)
			pr, err := collectProof(ctx, timeout, policy, submission)
			if err != nil {
				return nil, err
			}
			if pr != nil {
				proofs = append(proofs, *pr)
				break
			}
			if errInner := sleep(ctx); errInner != nil {
				return nil, errInner
			}
		}
	}
	return proofs, nil
}

// collectProof returns (non-nil, nil) when a proof was collected successfully.
// Returns an error if it seems unlikely that trying again will help.
func collectProof(ctx context.Context, timeout time.Duration, policy *policy.Policy, submission pendingSubmission) (*proof.SigsumProof, error) {
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pr := proof.SigsumProof{
		LogKeyHash: crypto.HashBytes(submission.log.entity.PublicKey[:]),
		Leaf:       submission.shortLeaf,
	}
	persisted, err := submission.log.client.AddLeaf(sctx, submission.request, submission.log.header)
	if err != nil {
		log.Debug("Checking that checksum was accepted: %v", err)
		return nil, nil // continue trying
	}
	if !persisted {
		log.Debug("Checking that checksum was sequenced: not yet")
		return nil, nil // continue trying
	}
	if pr.TreeHead, err = submission.log.client.GetTreeHead(sctx); err != nil {
		log.Debug("Getting latest tree head: %v", err)
		return nil, nil // continue trying
	}
	if err := policy.VerifyCosignedTreeHead(&pr.LogKeyHash, &pr.TreeHead); err != nil {
		log.Info("Verifying latest tree head: %v", err)
		return nil, nil // continue trying
	}
	req := requests.InclusionProof{Size: pr.TreeHead.Size, LeafHash: submission.leafHash}
	if pr.Inclusion, err = submission.log.client.GetInclusionProof(sctx, req); err != nil {
		log.Debug("Getting inclusion proof: %v", err)
		return nil, nil // continue trying
	}
	if err = pr.Inclusion.Verify(&submission.leafHash, &pr.TreeHead.TreeHead); err != nil {
		return nil, fmt.Errorf("Inclusion proof invalid: %v", err)
	}
	return &pr, nil
}
