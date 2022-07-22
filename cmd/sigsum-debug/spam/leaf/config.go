package leaf

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/sigsum-go/internal/fmtio"
	"git.sigsum.org/sigsum-go/pkg/types"
)

type Config struct {
	LogURL        string
	PrivateKey    string        // a private key to sign checksum with in hex
	DomainHint    string        // a domain hint that is valid for the above key
	Duration      time.Duration // how long to run test
	Interval      time.Duration // how often to emit stats
	Wait          time.Duration // time to wait between submits
	NumSubmitters uint64        // at least one
	NumCheckers   uint64        // zero to disable checkers

	url    string
	signer crypto.Signer
	pub    types.PublicKey
	cli    http.Client

	maxEvents int           // maximum number of events to queue at a checker
	backoff   time.Duration // time to backoff when waiting for 200 OK
}

func (cfg *Config) parse(args []string) (err error) {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %v", args)
	}
	if len(cfg.LogURL) == 0 {
		return fmt.Errorf("url is a required option")
	}
	if len(cfg.PrivateKey) == 0 {
		return fmt.Errorf("private key is a required option")
	}
	if len(cfg.DomainHint) == 0 {
		return fmt.Errorf("domain hint is a required option")
	}

	if cfg.signer, err = fmtio.SignerFromHex(cfg.PrivateKey); err != nil {
		return fmt.Errorf("parse private key: %v", err)
	}
	if cfg.NumSubmitters == 0 {
		return fmt.Errorf("at least one submitter is required")
	}

	cfg.url = types.EndpointAddLeaf.Path(cfg.LogURL, "sigsum/v0")
	cfg.maxEvents = 16384
	cfg.backoff = 5 * time.Second
	cfg.cli = http.Client{Timeout: 10 * time.Second}
	copy(cfg.pub[:], (cfg.signer.Public().(ed25519.PublicKey))[:])
	return nil
}
