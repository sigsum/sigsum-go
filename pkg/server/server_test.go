package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/mocks"
)

// Run HTTP request
func queryServer(t *testing.T, server http.Handler, method, url, body string) (*http.Response, string) {
	t.Helper()
	var reqBody io.Reader
	if len(body) > 0 {
		reqBody = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("creating http %s request for %q failed: %v", method, url, err)
	}

	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	result := w.Result()
	defer result.Body.Close()
	respBody, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("reading http response for %q failed: %v", url, err)
	}
	return result, string(respBody)
}

func TestGet(t *testing.T) {
	config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
	server := newServer(&config)
	server.register("get-x", http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprintf(w, "x-response\n")
			if err != nil {
				t.Fatalf("writing response failed: %v\n", err)
			}
		}))
	server.register("get-y/", http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			args := GetSigsumURLArguments(r)
			if len(args) == 0 {
				reportErrorCode(w, r.URL, http.StatusBadRequest, fmt.Errorf("missing y"))
				return
			}
			_, err := fmt.Fprintf(w, "y-response: %s\n", GetSigsumURLArguments(r))
			if err != nil {
				t.Fatalf("writing response failed: %v\n", err)
			}
		}))

	for _, table := range []struct {
		url             string
		status          int
		response        string
		htmlContentType bool
		usePost         bool
	}{
		{url: "/foo/get-x", status: 200, response: "x-response\n"},
		{url: "/foo/get-x", status: 405, usePost: true, response: "Method Not Allowed\n"},
		{url: "/foo/get-xx", status: 404},
		{url: "/foo/get-y", status: 301, htmlContentType: true},
		{url: "/foo/get-y/", status: 400, response: "missing y\n"},
		{url: "/foo/get-y/bar", status: 200, response: "y-response: bar\n"},
	} {
		method := "GET"
		if table.usePost {
			method = "POST"
		}
		result, body := queryServer(t, server, method, table.url, "")
		if got, want := result.StatusCode, table.status; got != want {
			t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
		}
		contentType := "text/plain; charset=utf-8"
		if table.htmlContentType {
			// For internally generated redirects or errors.
			contentType = "text/html; charset=utf-8"
		}
		if got, want := result.Header.Get("content-type"), contentType; got != want {
			t.Errorf("Unexpected content type for %q, got %q, want %q", table.url, got, want)
		}
		if got, want := body, table.response; got != want {
			if table.status == 200 || len(table.response) > 0 {
				t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
			}
		}
	}
}

func TestPost(t *testing.T) {
	config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
	server := newServer(&config)
	server.register("add-x", http.MethodPost,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("reading request failed: %v\n", err)
			}
			switch string(body) {
			default:
				reportErrorCode(w, r.URL, http.StatusBadRequest, fmt.Errorf("bad request %q", body))
			case "accept":
				reportError(w, r.URL, api.ErrAccepted)
			case "ok":
				_, err := fmt.Fprintf(w, "add-x ok\n")
				if err != nil {
					t.Fatalf("writing response failed: %v\n", err)
				}
			}
		}))
	for _, table := range []struct {
		url             string
		body            string
		status          int
		response        string
		htmlContentType bool
		useGet          bool
	}{
		{url: "/foo/add-x", body: "ok", status: 200, response: "add-x ok\n"},
		{url: "/foo/add-x", body: "accept", status: 202},
		{url: "/foo/add-x/", body: "ok", status: 404},
		{url: "/foo/add-x", body: "ok", status: 405, useGet: true},
	} {
		method := "POST"
		if table.useGet {
			method = "GET"
		}
		result, body := queryServer(t, server, method, table.url, table.body)
		if got, want := result.StatusCode, table.status; got != want {
			t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
		}
		contentType := "text/plain; charset=utf-8"
		if table.htmlContentType {
			// For internally generated redirects or errors.
			contentType = "text/html; charset=utf-8"
		}
		if got, want := result.Header.Get("content-type"), contentType; got != want {
			t.Errorf("Unexpected content type for %q, got %q, want %q", table.url, got, want)
		}
		if got, want := body, table.response; got != want {
			if table.status == 200 || len(table.response) > 0 {
				t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
			}
		}
	}
}

func TestMetrics(t *testing.T) {
	// If this delay is exceeded, don't fail test, just log a
	// warning, since we may be delayed due to bad luck in
	// scheduling on an overloaded machine.
	maxExpectedDelay := 100 * time.Millisecond

	// Just long enough to be noticable.
	testDelay := 200 * time.Millisecond

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch args := GetSigsumURLArguments(r); args {
		default:
			reportErrorCode(w, r.URL, http.StatusBadRequest, fmt.Errorf("bad request %q", args))
		case "ok":
			// Do nothing
		case "accept":
			reportError(w, r.URL, api.ErrAccepted)
		case "slow":
			time.Sleep(testDelay)
		}
	})
	for _, table := range []struct {
		url     string
		status  int
		usePost bool
		slow    bool
	}{
		{url: "/foo/get-x", status: 301},
		{url: "/foo/get-x/ok", status: 200},
		{url: "/foo/get-x/bad", status: 400},
		{url: "/foo/get-x/accept", status: 202},
		{url: "/foo/get-x/slow", status: 200, slow: true},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			metrics := mocks.NewMockMetrics(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute, Metrics: metrics}
			server := newServer(&config)
			server.register("get-x/", http.MethodGet, handler)
			method := "GET"
			if table.usePost {
				method = "POST"
			}
			if table.status != 301 {
				metrics.EXPECT().OnRequest("get-x/")
				metrics.EXPECT().OnResponse("get-x/", table.status, gomock.Any()).Do(
					func(_ string, _ int, latency time.Duration) {
						if table.slow {
							if latency < testDelay {
								t.Errorf("Expected latency (got %v) >= %v", latency, testDelay)
							}
						} else if latency > maxExpectedDelay {
							t.Logf("warn: Unexpectedly high latency (%v), expected at most %v", latency, maxExpectedDelay)
						}
					})

			}

			result, _ := queryServer(t, server, method, table.url, "")
			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
			}
		}()
	}
}
