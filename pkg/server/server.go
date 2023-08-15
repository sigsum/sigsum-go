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

type server struct {
	config Config
	mux    *http.ServeMux
}

func newServer(config *Config) *server {
	server := server{config: *config, mux: http.NewServeMux()}
	if server.config.Metrics == nil {
		server.config.Metrics = noMetrics{}
	}
	return &server
}

// Wrapper to check that the appropriate method is used. Also used to
// distinguish our registered handlers from internally generated ones.
type handlerWithMethod struct {
	method  string
	handler http.Handler
}

type sigsumUrlArguments struct{}

func (h *handlerWithMethod) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Error handling is based on RFC 7231, see Sections 6.5.5
	// (Status 405) and 6.5.1 (Status 400).
	if r.Method != h.method {
		statusCode := http.StatusBadRequest
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut:
			w.Header().Set("Allow", h.method)
			statusCode = http.StatusMethodNotAllowed
		}
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}
	h.handler.ServeHTTP(w, r)
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

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler, pattern := s.mux.Handler(r)
	if _, ok := handler.(*handlerWithMethod); !ok {
		// Some internally generated handler (redirect, or
		// page not found), just call it with no additional
		// processing.
		handler.ServeHTTP(w, r)
		return
	}
	s.config.Metrics.OnRequest(pattern)
	start := time.Now()

	response := responseWriterWithStatus{w: w, statusCode: http.StatusOK}
	defer func() {
		latency := time.Now().Sub(start)
		s.config.Metrics.OnResponse(pattern, response.statusCode, latency)
	}()

	ctx, cancel := context.WithTimeout(r.Context(), s.config.getTimeout())
	defer cancel()
	if strings.HasSuffix(pattern, "/") {
		ctx = context.WithValue(ctx, sigsumUrlArguments{},
			strings.TrimPrefix(r.URL.Path, pattern))
	}
	handler.ServeHTTP(&response, r.WithContext(ctx))
}

// Returns an empty string for missing arguments.
func GetSigsumURLArguments(r *http.Request) string {
	if args, ok := r.Context().Value(sigsumUrlArguments{}).(string); ok {
		return args
	}
	return ""
}

func (s *server) register(endpoint types.Endpoint, method string, handler http.Handler) {
	s.mux.Handle("/"+endpoint.Path(s.config.Prefix), &handlerWithMethod{method: method, handler: handler})
}

func reportErrorCode(w http.ResponseWriter, url *url.URL, statusCode int, err error) {
	// Log all internal server errors.
	if statusCode == http.StatusInternalServerError {
		log.Error("Internal server error for %q: %v", url.Path, err)
	} else {
		log.Debug("%q: status %d, %v", url.Path, statusCode, err)
	}
	http.Error(w, err.Error(), statusCode)
}

func reportError(w http.ResponseWriter, url *url.URL, err error) {
	reportErrorCode(w, url, api.ErrorStatusCode(err), err)
}
