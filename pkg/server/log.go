package server

import (
	"context"
	"fmt"
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

func newGetLeavesServer(config *Config, getLeaves func(context.Context, requests.Leaves) ([]types.Leaf, error)) *server {
	server := newServer(config)
	server.register(http.MethodGet, types.EndpointGetLeaves, "{start}/{end}",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.Leaves
			if err := req.FromURLArgs(r.PathValue("start"), r.PathValue("end")); err != nil {
				reportError(w, r.URL, api.ErrBadRequest.WithError(err))
				return
			}
			if req.StartIndex >= req.EndIndex {
				reportError(w, r.URL, api.ErrBadRequest.WithError(
					fmt.Errorf("start_index(%d) must be less than end_index(%d)",
						req.StartIndex, req.EndIndex)))
				return
			}
			leaves, err := getLeaves(r.Context(), req)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if got, max := uint64(len(leaves)), req.EndIndex-req.StartIndex; got == 0 || got > max {
				reportError(w, r.URL, fmt.Errorf("bad leaf count %d, should have 0 < count <= %d", got, max))
				return
			}
			if err := types.LeavesToASCII(w, leaves); err != nil {
				logError(r.URL, err)
			}
		}))
	return server
}

// Exported for the benefit of the primary node's internal endpoint.
func NewGetLeavesServer(config *Config, getLeaves func(context.Context, requests.Leaves) ([]types.Leaf, error)) http.Handler {
	return newGetLeavesServer(config, getLeaves)
}

// Returns a HTTP handler for a Sigsum log, represented by the passed
// in api.Log. The handler checks the validity of requests as far as
// possibly without knowledge of the log's current state. In
// particular, requests for trivial inclusion and consistency proofs
// are rejected, and not passed on to the underlying api.Log.
func NewLog(config *Config, log api.Log) http.Handler {
	server := newGetLeavesServer(config, log.GetLeaves)
	server.register(http.MethodGet, types.EndpointGetTreeHead, "",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cth, err := log.GetTreeHead(r.Context())
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if err = cth.ToASCII(w); err != nil {
				logError(r.URL, err)
			}
		}))
	server.register(http.MethodGet, types.EndpointGetInclusionProof, "{size}/{hash}",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.InclusionProof
			if err := req.FromURLArgs(r.PathValue("size"), r.PathValue("hash")); err != nil {
				reportError(w, r.URL, api.ErrBadRequest.WithError(err))
				return
			}
			if req.Size < 2 {
				// Size:0 => not possible to prove inclusion of anything
				// Size:1 => you don't need an inclusion proof (it is always empty)
				reportError(w, r.URL, api.ErrBadRequest.WithError(
					fmt.Errorf("size(%d) must be larger than one",
						req.Size)))
				return
			}
			proof, err := log.GetInclusionProof(r.Context(), req)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if err := proof.ToASCII(w); err != nil {
				logError(r.URL, err)
			}
		}))
	server.register(http.MethodGet, types.EndpointGetConsistencyProof, "{old}/{new}",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.ConsistencyProof
			if err := req.FromURLArgs(r.PathValue("old"), r.PathValue("new")); err != nil {
				reportError(w, r.URL, api.ErrBadRequest.WithError(err))
				return
			}
			if req.OldSize < 1 {
				reportError(w, r.URL, api.ErrBadRequest.WithError(
					fmt.Errorf("old_size(%d) must be larger than zero",
						req.OldSize)))
				return
			}
			if req.NewSize <= req.OldSize {
				reportError(w, r.URL, api.ErrBadRequest.WithError(
					fmt.Errorf("new_size(%d) must be larger than old_size(%d)",
						req.NewSize, req.OldSize)))
				return
			}
			proof, err := log.GetConsistencyProof(r.Context(), req)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if err := proof.ToASCII(w); err != nil {
				logError(r.URL, err)
			}
		}))
	server.register(http.MethodPost, types.EndpointAddLeaf, "",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.Leaf
			var submitHeader *token.SubmitHeader
			if err := req.FromASCII(r.Body); err != nil {
				reportError(w, r.URL, api.ErrBadRequest.WithError(err))
				return
			}
			if headerValue := r.Header.Get("Sigsum-Token"); len(headerValue) > 0 {
				submitHeader = &token.SubmitHeader{}
				if err := submitHeader.FromHeader(headerValue); err != nil {
					reportError(w, r.URL, api.ErrBadRequest.WithError(
						fmt.Errorf("Invalid Sigsum-Submit: header: %v", err)))
					return
				}
			}
			// TODO: Change AddLeaf to return api.ErrAccepted, instead of the persisted flag?
			persisted, err := log.AddLeaf(r.Context(), req, submitHeader)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if !persisted {
				reportError(w, r.URL, api.ErrAccepted)
			}
		}))

	return server
}
