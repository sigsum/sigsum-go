package server

import (
	"fmt"
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func NewWitness(config *Config, witness api.Witness) http.Handler {
	server := newServer(config)
	server.register(http.MethodPost, types.EndpointAddCheckpoint, "",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.AddCheckpoint
			if err := req.FromASCII(r.Body); err != nil {
				reportError(w, r.URL, api.ErrBadRequest.WithError(err))
				return
			}

			signatures, err := witness.AddCheckpoint(r.Context(), req)
			if err != nil {
				if oldSize, ok := api.ErrorConflictOldSize(err); ok {
					w.Header().Set("content-type", checkpoint.ContentTypeTlogSize)
					w.WriteHeader(http.StatusConflict)

					if _, err := fmt.Fprintf(w, "%d\n", oldSize); err != nil {
						logError(r.URL, err)
					}
					return
				}
				reportError(w, r.URL, err)
				return
			}

			for _, signature := range signatures {
				if err := signature.ToASCII(w); err != nil {
					logError(r.URL, err)
					return
				}
			}
		}))

	return server
}
