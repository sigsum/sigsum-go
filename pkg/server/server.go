// package server implements the http-layer of the Sigsum apis.
// It defines handlers for incoming HTTP requests, converting to
// request to a method call on the appropriate api interface. It checks
// for errors where it's clear that a request is bad according to the
// specs, regardless of what's backing the api interface. It converts
// the api method's return values (success or errors) into a http
// response to be returned to the client. Optionally, it can produce
// basic request and response metrics.
package server

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

type server struct {
	config Config
	mux    *http.ServeMux
}

func newServer(config *Config) *server {
	return &server{config: config.withDefaults(), mux: http.NewServeMux()}
}

// A response writer that records the status code.
type responseWriterWithStatus struct {
	statusCode int
	w          http.ResponseWriter
}

func (ws *responseWriterWithStatus) Header() http.Header {
	return ws.w.Header()
}

func (ws *responseWriterWithStatus) Write(data []byte) (int, error) {
	return ws.w.Write(data)
}
func (ws *responseWriterWithStatus) WriteHeader(statusCode int) {
	ws.statusCode = statusCode
	ws.w.WriteHeader(statusCode)
}

// Wrapper to produce metrics.
type handlerWithMetrics struct {
	config   *Config
	endpoint string
	handler  http.Handler
}

func (h *handlerWithMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.config.Metrics.OnRequest(h.endpoint)
	start := time.Now()

	response := responseWriterWithStatus{w: w, statusCode: http.StatusOK}
	defer func() {
		latency := time.Now().Sub(start)
		h.config.Metrics.OnResponse(h.endpoint, response.statusCode, latency)
	}()

	h.handler.ServeHTTP(&response, r)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.config.Timeout)
	defer cancel()
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

func (s *server) register(method string, endpoint types.Endpoint, args string, handler http.Handler) {
	s.mux.Handle(method+" /"+endpoint.Path(s.config.Prefix)+args,
		&handlerWithMetrics{config: &s.config, endpoint: string(endpoint), handler: handler})
}

// Note that it's not useful to report errors that occur when writing
// the response: It's too late to change the status code, and the
// likely reason for the error is that the client has disconnected.
func reportError(w http.ResponseWriter, url *url.URL, err error) {
	statusCode := api.ErrorStatusCode(err)
	if statusCode == http.StatusInternalServerError {
		log.Error("Internal server error for %q: %v", url.Path, err)
	} else {
		log.Debug("%q: status %d, %v", url.Path, statusCode, err)
	}
	http.Error(w, err.Error(), statusCode)
}

func logError(url *url.URL, err error) {
	log.Debug("%q: request failed: %v", url.Path, err)
}

var handlerBadRequest = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	reportError(w, r.URL, api.ErrBadRequest)
})
