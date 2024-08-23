package server

import (
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func NewWitness(config *Config, witness api.Witness) http.Handler {
	server := newServer(config)
	server.register(http.MethodGet, types.EndpointGetTreeSize, "{hash}",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.GetTreeSize
			if err := req.FromURLArgs(r.PathValue("hash")); err != nil {
				reportError(w, r.URL, api.ErrBadRequest.WithError(err))
				return
			}
			size, err := witness.GetTreeSize(r.Context(), req)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if err = ascii.WriteInt(w, "size", size); err != nil {
				logError(r.URL, err)
			}
		}))
	server.register(http.MethodPost, types.EndpointAddTreeHead, "",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.AddTreeHead
			if err := req.FromASCII(r.Body); err != nil {
				reportError(w, r.URL, api.ErrBadRequest.WithError(err))
				return
			}
			keyHash, cs, err := witness.AddTreeHead(r.Context(), req)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if err := cs.ToASCII(w, &keyHash); err != nil {
				logError(r.URL, err)
			}
		}))

	return server
}
