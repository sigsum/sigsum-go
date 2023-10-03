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
			if err == nil {
				err = sth.ToASCII(w)
			}
			if err != nil {
				reportError(w, r.URL, err)
			}
		}))
	return server
}
