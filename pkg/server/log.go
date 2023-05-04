package server

import (
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/types"
)

func LogServer(config *Config, log api.Log) http.Handler {
	server := newServer(config)
	server.register(types.EndpointGetTreeHead, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cth, err := log.GetTreeHead(r.Context())
			if err == nil {
				err = cth.ToASCII(w)
			}
			if err != nil {
				reportErrorCode(w, r.URL, http.StatusInternalServerError, err)
			}
		}))
	return server
}
