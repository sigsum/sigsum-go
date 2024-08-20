package submit

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

type ProofCallback func(proof.SigsumProof)

type itemState struct {
	// Provided by application
	req  requests.Leaf
	done ProofCallback
	// Managed by batch and submit logic.
	ctx      context.Context // Represents per-item timeout.
	leaf     types.Leaf
	leafHash crypto.Hash
}

type batchWorker struct {
	url        string
	logKeyHash crypto.Hash
	cli        api.Log
	header     *token.SubmitHeader

	// Incoming items for the worker.
	in chan *itemState
}

// Remove any nil elements.
func compactSlice[T any](s []*T) []*T {
	for i := 0; i < len(s); {
		if s[len(s)-1] == nil {
			s = s[:len(s)-1]
		} else if s[i] == nil {
			s[i] = s[len(s)-1]
			s = s[:len(s)-1]
		} else {
			i++
		}
	}
	return s
}

// Delete given item from slice. Panics if not present.
func deleteFromSlice[T comparable](s []T, x T) []T {
	for i := 0; i < len(s); i++ {
		if s[i] == x {
			s[i] = s[len(s)-1]
			return s[:len(s)-1]
		}
	}
	panic("item not found")
}

// Consumes the worker's input channel, each successful submit is sent on the done channel.
// On error, also returns the non-empty list of unfinished items.
func (w *batchWorker) run(ctx context.Context, done chan<- func(),
	policy *policy.Policy, pollDelay time.Duration) ([]*itemState, error) {

	// Input channel, set to nil when drained (so that it is
	// ignored in the select statement below).
	in := w.in

	// Latest seen tree size; only retry querying for inclusion
	// proofs when it grows.
	latestSize := uint64(0)

	var newItems, pendingItems []*itemState

	// For error return
	leftover := func(err error) ([]*itemState, error) {
		return append(compactSlice(newItems), compactSlice(pendingItems)...), err
	}

	// Pass on the result of a successful submit.
	result := func(callback ProofCallback, pr *proof.SigsumProof) {
		done <- func() { callback(*pr) }
	}

	// Wait until we get a new item, or it's time to poll log, or
	// the context is cancelled.
	poll := func() error {
		var pollTime <-chan time.Time

		if len(newItems) > 0 || len(pendingItems) > 0 {
			timer := time.NewTimer(pollDelay)
			defer timer.Stop()
			pollTime = timer.C
		}
		select {
		case item, ok := <-in:
			if !ok {
				in = nil
			} else {
				newItems = append(newItems, item)
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-pollTime:
		}
		return nil
	}

	log.Info("Starting worker for log %s", w.url)
	for in != nil || len(newItems) > 0 || len(pendingItems) > 0 {
		log.Debug("worker %s: new %d, pending %d",
			w.url, len(newItems), len(pendingItems))

		if err := poll(); err != nil {
			return leftover(err)
		}

		for i, item := range newItems {
			persisted, err := w.cli.AddLeaf(item.ctx, item.req, w.header)
			if err != nil {
				return leftover(err)
			}
			if persisted {
				pendingItems = append(pendingItems, item)
				newItems[i] = nil
				// Since it's possible that the leaf is an old one, and not actually added to the tree now,
				// we should ask for an inclusion proof regardless of previous tree size seen.
				latestSize = 0
			}
		}
		newItems = compactSlice(newItems)

		if len(pendingItems) > 0 {
			th, err := w.cli.GetTreeHead(ctx)
			if err != nil {
				return leftover(err)
			}
			// TODO: Keep trying, in case some witness is temporarily offline?
			if err := policy.VerifyCosignedTreeHead(&w.logKeyHash, &th); err != nil {
				return leftover(fmt.Errorf("verifying tree head failed: %v", err))
			}
			if th.Size > latestSize {
				log.Info("New tree size %d for log %s", th.Size, w.url)

				latestSize = th.Size
				for i, item := range pendingItems {
					var inclusionProof types.InclusionProof
					var err error
					if th.Size > 1 {
						// TODO: Make GetInclusionProof handle any tree size (and talk to the server only for size > 1).
						inclusionProof, err = w.cli.GetInclusionProof(item.ctx, requests.InclusionProof{
							Size:     th.Size,
							LeafHash: item.leafHash,
						})
					}
					if err != nil {
						if errors.Is(err, api.ErrNotFound) {
							continue
						}
						return leftover(err)
					}

					if err := inclusionProof.Verify(&item.leafHash, &th.TreeHead); err != nil {
						return leftover(err)
					}

					pendingItems[i] = nil
					result(item.done,
						&proof.SigsumProof{LogKeyHash: w.logKeyHash,
							Leaf:      proof.NewShortLeaf(&item.leaf),
							TreeHead:  th,
							Inclusion: inclusionProof,
						})
				}
				pendingItems = compactSlice(pendingItems)
			}
		}
	}
	return nil, nil
}

func runWorkers(ctx context.Context, config *Config, workers []*batchWorker, in chan *itemState, out chan<- func()) {
	var wg sync.WaitGroup
	closing := make(chan *batchWorker, len(workers))

	for _, worker := range workers {
		wg.Add(1)
		go func(worker *batchWorker) {
			items, err := worker.run(ctx, out, config.Policy, config.PollDelay)
			if err != nil {
				log.Warning("Log worker %s failed: %v", worker.url, err)

				closing <- worker // Never blocks, due to above capacity.

				// To avoid deadlock, drain input
				// channel before issuing retries.
				// There should be at most one more
				// incoming item after above send to
				// the closing channel.
				for item := range worker.in {
					items = append(items, item)
				}

				// Send items back, for retry on some other worker.
				for _, item := range items {
					in <- item
				}
			}
			log.Info("Log worker %s done", worker.url)
			wg.Done()
		}(worker) // Must evaluate the worker variable outside of the go call.
	}

	// Multiplex incoming items.
	next := 0

loop:
	for {
		// Process any closing workers first.
		for len(closing) > 0 {
			worker := <-closing
			close(worker.in)
			workers = deleteFromSlice(workers, worker)
		}
		select {
		case worker := <-closing:
			close(worker.in)
			workers = deleteFromSlice(workers, worker)
		case item, ok := <-in:
			if !ok {
				break loop
			}

			if len(workers) == 0 {
				// Send a nil output, to indicate an item was discarded.
				out <- nil
			} else {
				if next >= len(workers) {
					next = 0
				}

				// TODO: This context is never cancelled.
				item.ctx, _ = context.WithTimeout(ctx, config.PerLogTimeout)
				// From the above close processing, we'll submit at most one new item
				// to a worker after it has sent its closing message.
				workers[next].in <- item
				next++
			}
		}
	}
	for i := 0; i < len(workers); i++ {
		close(workers[i].in)
	}
	wg.Wait()
	close(closing)
}

type batchStatus int

const (
	batchOpen    = iota // Accepts new requests.
	batchWaiting        // Waiting, can accept new requests after Wait is finished.
	batchClosed         // Closed.
)

type Batch struct {
	// Counts pending items.
	pending sync.WaitGroup

	done chan struct{}
	in   chan *itemState

	m      sync.Mutex
	status batchStatus
	lost   int // Failure count.
}

func newBatchWithWorkers(ctx context.Context, config *Config,
	workers []*batchWorker) *Batch {
	batch := Batch{
		done: make(chan struct{}),
		in:   make(chan *itemState),
	}
	go batch.run(ctx, config.withDefaults(), workers)
	return &batch
}

// TODO: Define behavior when ctx is cancelled.
func NewBatch(ctx context.Context, config *Config) (*Batch, error) {
	logs := config.Policy.GetLogsWithUrl()
	if len(logs) == 0 {
		return nil, fmt.Errorf("no logs defined in policy")
	}
	var workers []*batchWorker

	for _, entity := range logs {
		var header *token.SubmitHeader
		if config.RateLimitSigner != nil && len(config.Domain) > 0 {
			signature, err := token.MakeToken(config.RateLimitSigner, &entity.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("creating submit token failed: %v", err)
			}
			header = &token.SubmitHeader{Domain: config.Domain, Token: signature}
		}

		workers = append(workers, &batchWorker{
			url:        entity.URL,
			logKeyHash: crypto.HashBytes(entity.PublicKey[:]),
			cli: client.New(client.Config{
				UserAgent:  config.UserAgent,
				URL:        entity.URL,
				HTTPClient: config.HTTPClient,
			}),
			header: header,
			in:     make(chan *itemState),
		})
	}
	return newBatchWithWorkers(ctx, config, workers), nil
}

// The done callback is invoked with the resulting proof when the
// submission succeeds. All callbacks are invoked sequentially, from
// the same goroutine. It is expected to return quickly, otherwise it
// will block the batch processing. The callback must *not* call any
// methods on the Batch object, since doing so may deadlock.
func (b *Batch) SubmitMessage(signer crypto.Signer, message *crypto.Hash, done ProofCallback) error {
	signature, err := types.SignLeafMessage(signer, message[:])
	if err != nil {
		return err
	}
	return b.SubmitLeafRequest(&requests.Leaf{
		Message:   *message,
		Signature: signature,
		PublicKey: signer.Public(),
	}, done)
}

func (b *Batch) SubmitLeafRequest(req *requests.Leaf, done ProofCallback) error {
	item := itemState{req: *req, done: done}
	var err error
	item.leaf, err = req.Verify()
	if err != nil {
		return fmt.Errorf("verifying leaf request failed: %v", err)
	}
	item.leafHash = item.leaf.ToHash()

	b.m.Lock()
	defer b.m.Unlock()
	if b.status != batchOpen {
		return fmt.Errorf("attempt to submit a leaf to a batch that is not open")
	}
	// TODO: Return error early in case there are no active workers?
	b.pending.Add(1)
	b.in <- &item
	return nil
}

func (b *Batch) run(ctx context.Context, config Config, workers []*batchWorker) {
	out := make(chan func())

	go func() {
		runWorkers(ctx, &config, workers, b.in, out)
		close(out)
	}()

	for f := range out {
		if f != nil {
			f()
		} else {
			b.m.Lock()
			b.lost++
			b.m.Unlock()
		}
		b.pending.Done()
	}
	close(b.done)
}

// Waits for all pending requests to complete.
func (b *Batch) Wait() error {
	setWaiting := func() error {
		b.m.Lock()
		defer b.m.Unlock()
		if b.status != batchOpen {
			return fmt.Errorf("invalid state, calling Wait on a Batch that is already Waiting")
		}
		b.status = batchWaiting
		return nil
	}

	if err := setWaiting(); err != nil {
		return err
	}
	// Waits for processing of all items to complete or timeout.
	b.pending.Wait()

	b.m.Lock()
	defer b.m.Unlock()
	if b.lost > 0 {
		b.status = batchClosed
		return fmt.Errorf("%d items of the batch failed", b.lost)
	}
	b.status = batchOpen
	return nil
}

func (b *Batch) Close() error {
	setWaiting := func() (bool, error) {
		b.m.Lock()
		defer b.m.Unlock()
		if b.status == batchClosed {
			return true, nil
		}
		if b.status != batchOpen {
			return false, fmt.Errorf("invalid state, calling Close on a Batch that is already Waiting")
		}
		b.status = batchWaiting
		return false, nil
	}

	if closed, err := setWaiting(); closed || err != nil {
		return err
	}

	// Waits for processing of all items to complete or timeout.
	b.pending.Wait()
	close(b.in)

	<-b.done

	b.m.Lock()
	defer b.m.Unlock()
	b.status = batchClosed

	if b.lost > 0 {
		return fmt.Errorf("%d items of the batch failed", b.lost)
	}
	return nil
}