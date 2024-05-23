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

	// For communicating with the go routine
	c chan *itemState
}

func (b *batchWorker) submit(item *itemState) {
	b.c <- item
}

func (b *batchWorker) close() {
	close(b.c)
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

// Delete given item from slice. Returns true if the item was found
// and deleted.
func deleteFromSlice[T comparable](s []T, x T) ([]T, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == x {
			s[i] = s[len(s)-1]
			return s[:len(s)-1], true
		}
	}
	return s, false
}

// All sent on the same channel, to get a well-defined order between
// failures and retries. There are three cases:
//
//   - Worker failure: w, err non-nil.
//
//   - Item success: item and pr non-nil.
//
//   - Item retry: item non-nil, pr nil. Should be sent to a worker for
//     which there's no preceding failure.
type workerOutput struct {
	w    *batchWorker
	err  error
	item *itemState
	pr   *proof.SigsumProof
}

// Any failure is reported via the done channel. Does not return until
// the in channel is drained. Both completed (non-nil proof) and
// incomplete items are send on the out channel.
func (w *batchWorker) run(ctx context.Context, out chan<- workerOutput,
	policy *policy.Policy, pollDelay time.Duration) {

	latestSize := uint64(0)

	var newItems, pendingItems []*itemState

	// Input channel, set to nil when drained (so that it is
	// ignored in the select statement below).
	in := w.c

	log.Debug("Starting runner for log %s", w.url)
loop:
	for in != nil || len(newItems) > 0 || len(pendingItems) > 0 {
		log.Debug("new: %d, pending: %d", len(newItems), len(pendingItems))

		if err := func() error {
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
		}(); err != nil {
			out <- workerOutput{w: w, err: err}
			break loop
		}

		for i, item := range newItems {
			persisted, err := w.cli.AddLeaf(item.ctx, item.req, w.header)
			log.Debug("Add leaf request resp: %v, %v", persisted, err)
			if err != nil {
				out <- workerOutput{w: w, err: err}
				break loop
			}
			if persisted {
				pendingItems = append(pendingItems, item)
				newItems[i] = nil
			}
		}
		newItems = compactSlice(newItems)

		if len(pendingItems) > 0 {
			log.Debug("Process pending items")
			th, err := w.cli.GetTreeHead(ctx)
			if err != nil {
				out <- workerOutput{w: w, err: err}
				break loop
			}
			log.Debug("Got tree head size %d", th.Size)
			// TODO: Keep trying, in case some witness is temporarily offline?
			if err := policy.VerifyCosignedTreeHead(&w.logKeyHash, &th); err != nil {
				out <- workerOutput{w: w, err: fmt.Errorf("verifying tree head failed: %v", err)}
				break loop
			}
			if th.Size > latestSize {
				log.Debug("Querying for inclusion proofs")

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
					if err == nil {
						log.Debug("Got proof, index %d", inclusionProof.LeafIndex)
						if err := inclusionProof.Verify(&item.leafHash, &th.TreeHead); err != nil {
							out <- workerOutput{w: w, err: err}
							break loop
						}

						pendingItems[i] = nil
						out <- workerOutput{item: item,
							pr: &proof.SigsumProof{LogKeyHash: w.logKeyHash,
								Leaf:      proof.NewShortLeaf(&item.leaf),
								TreeHead:  th,
								Inclusion: inclusionProof,
							}}
					} else if !errors.Is(err, api.ErrNotFound) {
						out <- workerOutput{w: w, err: err}
						break loop
					}
				}
				pendingItems = compactSlice(pendingItems)
			}
		}
	}

	// Submit any left-over messages for retry. At this point,
	// either the input channel is already closed, or we have sent
	// a failure message requesting that it be closed. In either
	// case, the items we send here can not come back to us.
	for _, item := range newItems {
		if item != nil {
			out <- workerOutput{item: item}
		}
	}
	for _, item := range pendingItems {
		if item != nil {
			out <- workerOutput{item: item}
		}
	}
	if in != nil {
		for item := range in {
			out <- workerOutput{item: item}
		}
	}
}

type batchStatus int

const (
	batchOpen    = iota // Accepts new requests.
	batchWaiting        // Waiting, can accept new requests after Wait is finished.
	batchClosed         // Closed.
)

type Batch struct {
	ctx    context.Context
	config Config

	// Counts pending items.
	pending sync.WaitGroup

	done chan struct{}

	m       sync.Mutex
	status  batchStatus
	workers []*batchWorker
	// For round-robin scheduling.
	nextWorker int
	// Count of failed items.
	lost int
}

func newBatchWithWorkers(ctx context.Context, config *Config,
	workers []*batchWorker) *Batch {

	batch := Batch{
		ctx:     ctx,
		config:  config.withDefaults(),
		workers: workers,
		done:    make(chan struct{}),
	}
	go batch.run()
	return &batch
}

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
			c:      make(chan *itemState),
		})
	}
	return newBatchWithWorkers(ctx, config, workers), nil
}

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
	b.submitUnlocked(&item)
	return nil
}

// Submits an item to one log, resetting the per item timeout.
func (b *Batch) submitUnlocked(item *itemState) {
	if len(b.workers) == 0 {
		b.pending.Done()
		b.lost++
		return
	}

	// TODO: This context is never cancelled.
	item.ctx, _ = context.WithTimeout(b.ctx, b.config.PerLogTimeout)

	log.Debug("submitting to worker %d: %s", b.nextWorker, b.workers[b.nextWorker].url)
	b.workers[b.nextWorker].submit(item)
	b.nextWorker = (b.nextWorker + 1) % len(b.workers)
}
func (b *Batch) submit(item *itemState) {
	b.m.Lock()
	defer b.m.Unlock()
	b.submitUnlocked(item)
}

// Close worker's channel, and remove from list. Does nothing if
// worker is already closed.
func (b *Batch) closeWorker(w *batchWorker) {
	b.m.Lock()
	defer b.m.Unlock()

	var deleted bool
	b.workers, deleted = deleteFromSlice(b.workers, w)
	if !deleted {
		return
	}
	w.close()
	if b.nextWorker >= len(b.workers) {
		b.nextWorker = 0
	}
}

func (b *Batch) run() {
	out := make(chan workerOutput)
	var wg sync.WaitGroup

	log.Debug("Starting workers")

	for _, worker := range b.workers {
		wg.Add(1)
		go func(worker *batchWorker) {
			worker.run(b.ctx, out, b.config.Policy, b.config.PollDelay)
			log.Info("Log worker %s done", worker.url)
			wg.Done()
		}(worker) // Must evaluate the worker variable outside of the go call.
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	for output := range out {
		log.Debug("output: %#v", output)
		switch {
		case output.err != nil:
			log.Warning("Log worker %s failed: %v", output.w.url, output.err)
			b.closeWorker(output.w)
		case output.pr != nil:
			output.item.done(*output.pr)
			b.pending.Done()
		case output.item != nil:
			// Retry on a different log. Done
			// concurrently, since we'd deadlock if we
			// block waiting for the worker to be ready to
			// receive the item, at the same time as the
			// worker blocks on us to get ready to receive
			// the worker's output. TODO: Spawn a single
			// longer-lived goroutine for retries?
			go b.submit(output.item)
		default:
			panic(fmt.Sprintf("internal error, unexpected worker output: %#v", output))
		}
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
	b.status = batchOpen
	lost := b.lost
	b.lost = 0

	if lost != 0 {
		return fmt.Errorf("%d items of the batch failed", lost)
	}
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
			return false, fmt.Errorf("invalid state, calling Wait on a Batch that is already Waiting")
		}
		b.status = batchWaiting
		return false, nil
	}

	closeWorkers := func() int {
		b.m.Lock()
		defer b.m.Unlock()
		b.status = batchClosed
		for _, w := range b.workers {
			w.close()
		}
		b.workers = nil
		return b.lost
	}

	if closed, err := setWaiting(); closed || err != nil {
		return err
	}

	// Waits for processing of all items to complete or timeout.
	b.pending.Wait()

	lost := closeWorkers()
	<-b.done

	if lost != 0 {
		return fmt.Errorf("%d items of the batch failed", lost)
	}
	return nil
}
