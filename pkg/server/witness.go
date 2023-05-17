package server

import (
	"fmt"
	"net/http"

	// TODO: We shouldn't depend on the client package. Move
	// shared interfaces and errors elsewhere, possibly to an api
	// package.
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func NewWitness(config *Config, witness client.Witness) http.Handler {
	server := newServer(config)
	server.register(types.EndpointGetTreeSize, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.GetTreeSize
			// TODO: Take prefix into account, see
			// https://git.glasklar.is/sigsum/core/log-go/-/issues/50
			if err := req.FromURL(r.URL.Path); err != nil {
				reportErrorCode(w, r.URL, http.StatusBadRequest, err)
				return
			}
			size, err := witness.GetTreeSize(r.Context(), req)
			if err == nil {
				_, err = fmt.Fprintf(w, "size=%d", size)
			}
			if err != nil {
				reportErrorCode(w, r.URL, http.StatusInternalServerError, err)
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
			if err == nil {
				err = cs.ToASCII(w)
			}
			if err != nil {
				reportError(w, r.URL, err)
			}
		}))

	return server
}
