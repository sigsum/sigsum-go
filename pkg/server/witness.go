package server

import (
	"fmt"
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func NewWitness(config *Config, witness api.Witness) http.Handler {
	server := newServer(config)
	server.register(types.EndpointGetTreeSize, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.GetTreeSize
			if err := req.FromURLArgs(GetSigsumURLArguments(r)); err != nil {
				reportErrorCode(w, r.URL, http.StatusBadRequest, err)
				return
			}
			size, err := witness.GetTreeSize(r.Context(), req)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if _, err = fmt.Fprintf(w, "size=%d", size); err != nil {
				reportError(w, r.URL, err)
			}
		}))
	server.register(types.EndpointAddTreeHead, http.MethodPost,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.AddTreeHead
			if err := req.FromASCII(r.Body); err != nil {
				reportErrorCode(w, r.URL, http.StatusBadRequest, err)
				return
			}
			cs, err := witness.AddTreeHead(r.Context(), req)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if err := cs.ToASCII(w); err != nil {
				reportError(w, r.URL, err)
			}
		}))

	return server
}
