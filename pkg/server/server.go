// package server implements the http-layer of the Sigsum apis.
// It defines handlers for incoming HTTP requests, converting to
// request to a method call on the appropriate api interface. It checks
// for errors where it's clear that a request is bad according to the
// specs, regardless of what's backing the api interface. It converts
// the api method's return values (success or errors) into a http
// response to be returned to the client. Optionally, handlers can be
// wrapped with middleware to perform tasks such as recording metrics.
package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

type Middleware func(http.Handler) http.Handler

func chain(middlewares ...Middleware) Middleware {
	return func(h http.Handler) http.Handler {
		for i := len(middlewares); i > 0; i-- {
			h = middlewares[i-1](h)
		}
		return h
	}
}

type endpointContextKey struct{}

// EndpointFromContext returns the endpoint stored in ctx, or an empty
// string if no endpoint is present.
func EndpointFromContext(ctx context.Context) string {
	v, _ := ctx.Value(endpointContextKey{}).(string)
	return v
}

func withEndpoint(endpoint string, next http.Handler) http.Handler {
	endpoint = strings.TrimSuffix(endpoint, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), endpointContextKey{}, endpoint))
		next.ServeHTTP(w, r)
	})
}

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

func (s *server) register(method string, endpoint types.Endpoint, args string, h http.Handler) {
	h = chain(s.config.Middlewares...)(h)
	h = &handlerWithMetrics{config: &s.config, endpoint: string(endpoint), handler: h}
	h = withEndpoint(string(endpoint), h)
	s.mux.Handle(method+" /"+endpoint.Path(s.config.Prefix)+args, h)
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
