package server

import (
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/types"
)

func NewSecondary(config *Config, secondary api.Secondary) http.Handler {
	server := newServer(config)
	server.register(types.EndpointGetSecondaryTreeHead, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sth, err := secondary.GetSecondaryTreeHead(r.Context())
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if err := sth.ToASCII(w); err != nil {
				reportError(w, r.URL, err)
			}
		}))
	return server
}
