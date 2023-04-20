package monitor

import (
	"context"
	"fmt"
	"time"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type AlertType int

const (
	AlertOther AlertType = iota
	// Indicates log is misbehaving, or not responding.
	AlertLogError
	AlertInvalidLogSignature
	AlertInconsistentTreeHead
)

func (t AlertType) String() string {
	switch t {
	case AlertOther:
		return "Other"

	case AlertLogError:
		return "Log not responding as expected"
	case AlertInvalidLogSignature:
		return "Invalid log signature"
	case AlertInconsistentTreeHead:
		return "Log tree head not consistent"
	default:
		return fmt.Sprintf("Unknown alert type %d", t)
	}
}

type Alert struct {
	Type AlertType
	Err  error
}

func (a *Alert) Error() string {
	return fmt.Sprintf("monitoring alert: %s: %s", a.Type, a.Err)
}

func newAlert(t AlertType, msg string, args ...interface{}) *Alert {
	return &Alert{Type: t, Err: fmt.Errorf(msg, args...)}
}

type Callbacks interface {
	// Called when a log (identified by key hash) has a new tree
	// head; application can use this to persist the tree head.
	// TODO: Also include cosignatures?
	NewTreeHead(logKeyHash crypto.Hash, signedTreeHead types.SignedTreeHead)
	// Called when there are new leaves with submit key of
	// interest. Includes only leaves with a known submit key, and
	// where signature and inclusion proof are valid.
	NewLeaves(logKeyHash crypto.Hash, leaves []types.Leaf)
	Alert(logKeyHash crypto.Hash, e error)
}

// State for monitoring a single sigsum log. A monitor program is
// expected to have one instance and one goroutine per log it
// monitors.
type Monitor struct {
	logKey crypto.PublicKey // Identifies the log monitored.
	// Keys of interest. If nil, all keys are of interest (but no
	// signatures are verified(.
	submitKeys map[crypto.Hash]crypto.PublicKey

	client client.Log
	// Latest processed valid tree head.
	treeHead types.TreeHead
}

// Queries the log for a new tree head. Get any new leaves, verify
// inclusion of all leaves, and extract the ones that match a known
// submitter key.
func (m *Monitor) Update(ctx context.Context) ([]types.Leaf, *types.SignedTreeHead, error) {
	cth, err := m.client.GetTreeHead(ctx)
	if err != nil {
		return nil, nil, newAlert(AlertLogError, "get-tree-head failed: %v", err)
	}
	// For now, only check log's signature. TODO: Also check cosignatures.
	if !cth.Verify(&m.logKey) {
		return nil, nil, newAlert(AlertInvalidLogSignature, "log signature invalid")
	}
	if cth.Size < m.treeHead.Size {
		return nil, nil, newAlert(AlertInconsistentTreeHead, "monitored log has shrunk, size %d, previous size %d", cth.Size, m.treeHead.Size)
	}
	if cth.Size == m.treeHead.Size {
		return nil, nil, nil
	}
	if m.treeHead.Size > 0 {
		proof, err := m.client.GetConsistencyProof(ctx, requests.ConsistencyProof{OldSize: m.treeHead.Size, NewSize: cth.Size})
		if err != nil {
			return nil, nil, newAlert(AlertLogError, "get-consistency-proof failed: %v", err)
		}

		if err := proof.Verify(&m.treeHead, &cth.TreeHead); err != nil {
			return nil, nil, newAlert(AlertInconsistentTreeHead, "consistency proof not valid: %v", err)
		}
	}
	var matchedLeaves []types.Leaf = nil
	// TODO: Get leaves in batches, and verify them all based on a single inclusion proof.
	for i := m.treeHead.Size; i < cth.Size; i++ {
		leaves, err := m.client.GetLeaves(ctx, requests.Leaves{StartIndex: i, EndIndex: i + 1})
		if err != nil {
			return nil, nil, err
		}
		if len(leaves) != 1 {
			return nil, nil, newAlert(AlertLogError, "invalid get-leaves response, got %d leaves, expected 1", len(leaves))
		}
		leaf := leaves[0]
		leafHash := leaf.ToHash()
		proof, err := m.client.GetInclusionProof(ctx,
			requests.InclusionProof{Size: cth.Size, LeafHash: leafHash})
		if err != nil {
			return nil, nil, newAlert(AlertLogError, "get-inclusion-proof failed")
		}
		if err := proof.Verify(&leafHash, &cth.TreeHead); err != nil {
			return nil, nil, newAlert(AlertLogError, "inclusion proof not valid")
		}
		if m.submitKeys != nil {
			if key, ok := m.submitKeys[leaf.KeyHash]; ok {
				if !leaf.Verify(&key) {
					// Indicates log is misbehaving.
					return nil, nil, newAlert(AlertLogError, "invalid leaf signature, keyhash %x", leaf.KeyHash)
				}
				matchedLeaves = append(matchedLeaves, leaf)
			}
		} else {
			matchedLeaves = append(matchedLeaves, leaf)
		}
	}
	m.treeHead = cth.TreeHead
	return matchedLeaves, &cth.SignedTreeHead, nil
}

func (m *Monitor) Run(ctx context.Context, interval time.Duration, callbacks Callbacks) {
	keyHash := crypto.HashBytes(m.logKey[:])
	for ctx.Err() == nil {
		updateCtx, _ := context.WithTimeout(ctx, interval)
		leaves, sth, e := m.Update(ctx)
		if e != nil {
			callbacks.Alert(keyHash, e)
		} else {
			if sth != nil {
				callbacks.NewTreeHead(keyHash, *sth)
			}
			if leaves != nil {
				callbacks.NewLeaves(keyHash, leaves)
			}
		}
		// Waits until end of interval
		<-updateCtx.Done()
	}
}

// Runs monitor in the background, until ctx is cancelled.
func StartMonitoring(
	ctx context.Context, p *policy.Policy,
	interval time.Duration,
	submitKeys map[crypto.Hash]crypto.PublicKey,
	state map[crypto.Hash]types.SignedTreeHead,
	callbacks Callbacks) error {
	monitors := []Monitor{}
	for _, l := range p.GetLogsWithUrl() {
		keyHash := crypto.HashBytes(l.PublicKey[:])
		monitor := Monitor{
			logKey:     l.PublicKey,
			submitKeys: submitKeys,
			client:     client.New(client.Config{URL: l.URL, UserAgent: "sigsum-monitor"}),
		}
		if sth, ok := state[keyHash]; ok {
			if !sth.Verify(&l.PublicKey) {
				return fmt.Errorf("invalid signature in old state for log %q", keyHash)
			}
			monitor.treeHead = sth.TreeHead
		} else {
			monitor.treeHead = types.NewEmptyTreeHead()
		}
		monitors = append(monitors, monitor)
	}
	for _, m := range monitors {
		go m.Run(ctx, interval, callbacks)
	}
	return nil
}
