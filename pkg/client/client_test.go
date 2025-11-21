package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/internal/mocks"
	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/requests"
	token "sigsum.org/sigsum-go/pkg/submit-token"
)

func newTestConfig(transport http.RoundTripper) Config {
	return Config{
		UserAgent: "sigsum unit test",
		URL:       "http://example.org/api",
		HTTPClient: &http.Client{
			Transport: transport,
		},
	}
}

type requestMatcher struct {
	method, url string
}

func (m *requestMatcher) Matches(x any) bool {
	if req, ok := x.(*http.Request); ok {
		return req.Method == m.method && req.URL.String() == m.url
	}
	return false
}

func (m *requestMatcher) String() string {
	return fmt.Sprintf("%s request to %s", m.method, m.url)
}

func getRequestTo(url string) gomock.Matcher {
	return &requestMatcher{method: http.MethodGet, url: url}
}

func postRequestTo(url string) gomock.Matcher {
	return &requestMatcher{method: http.MethodPost, url: url}
}

type headerMatcher struct {
	key, value string
}

func (m *headerMatcher) Matches(x any) bool {
	if req, ok := x.(*http.Request); ok {
		return req.Header.Get(m.key) == m.value
	}
	return false
}

func (m *headerMatcher) String() string {
	return fmt.Sprintf("with %s: %s header", m.key, m.value)
}

func withHeader(key, value string) gomock.Matcher {
	return &headerMatcher{key: key, value: value}
}

func newResponse(code int, body string) *http.Response {
	return &http.Response{
		Status:     http.StatusText(code),
		StatusCode: code,
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

func TestGetSecondaryTreeHead(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-secondary-tree-head")).Return(
		newResponse(http.StatusOK, `
size=3
root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
signature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
`[1:]), nil)
	sth, err := client.GetSecondaryTreeHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sth.Size, uint64(3); got != want {
		t.Errorf("unexpected tree size, got %d, want %d", got, want)
	}
}

func TestGetTreeHead(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-tree-head")).Return(
		newResponse(http.StatusOK, `
size=3
root_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
signature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
cosignature=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 4711 ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
`[1:]), nil)
	cth, err := client.GetTreeHead(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	if got, want := cth.Size, uint64(3); got != want {
		t.Errorf("unexpected tree size, got %d, want %d", got, want)
	}
	if got, want := len(cth.Cosignatures), 1; got != want {
		t.Errorf("unexpected # cosignatures, got %d, want %d", got, want)
	}
	for _, cs := range cth.Cosignatures {
		if got, want := cs.Timestamp, uint64(4711); got != want {
			t.Errorf("unexpected timestamp, got %d, want %d", got, want)
		}
	}
}

func TestGetInclusionProof(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-inclusion-proof/5/0000000000000000000000000000000000000000000000000000000000000000")).Return(
		newResponse(http.StatusOK, `
leaf_index=3
node_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
node_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`[1:]), nil)
	if _, err := client.GetInclusionProof(context.Background(),
		requests.InclusionProof{Size: 0}); err != api.ErrNotFound {
		t.Errorf("not the right error for size = 0, got %v, wanted api.ErrNotFound", err)
	}
	if proof, err := client.GetInclusionProof(context.Background(),
		requests.InclusionProof{Size: 1}); err != nil {
		t.Errorf("unexpected error for size = 1: %v", err)
	} else if got, want := len(proof.Path), 0; got != want {
		t.Errorf("unexpected inclusion path length, got %d, want %d", got, want)
	}
	if proof, err := client.GetInclusionProof(context.Background(),
		requests.InclusionProof{Size: 5}); err != nil {
		t.Errorf("unexpected error for size = 1: %v", err)
	} else {
		if got, want := len(proof.Path), 2; got != want {
			t.Errorf("unexpected inclusion path length, got %d, want %d", got, want)
		}
		if got, want := proof.LeafIndex, uint64(3); got != want {
			t.Errorf("unexpected leaf index, got %d, want %d", got, want)
		}
	}
}

func TestGetConsistencyProof(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-consistency-proof/5/10")).Return(
		newResponse(http.StatusOK, `
node_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
node_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`[1:]), nil)
	if proof, err := client.GetConsistencyProof(context.Background(),
		requests.ConsistencyProof{OldSize: 0, NewSize: 10}); err != nil {
		t.Errorf("unexpected error for old size = 0: %v", err)
	} else if len(proof.Path) > 0 {
		t.Errorf("unexpected non-empty path for old size = 0: %x", proof.Path)
	}

	if proof, err := client.GetConsistencyProof(context.Background(),
		requests.ConsistencyProof{OldSize: 10, NewSize: 10}); err != nil {
		t.Errorf("unexpected error for old size = new size = 10: %v", err)
	} else if len(proof.Path) > 0 {
		t.Errorf("unexpected non-empty path for old size = new size = 10: %x", proof.Path)
	}

	if proof, err := client.GetConsistencyProof(context.Background(),
		requests.ConsistencyProof{OldSize: 5, NewSize: 10}); err != nil {
		t.Errorf("unexpected error for old size = 5, new size = 10: %v", err)
	} else if got, want := len(proof.Path), 2; got != want {
		t.Errorf("unexpected consistency inclusion path length, got %d, want %d", got, want)
	}
}

func TestGetLeaves(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-leaves/5/10")).Return(
		newResponse(http.StatusOK, `
leaf=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
leaf=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
`[1:]), nil)
	if _, err := client.GetLeaves(context.Background(), requests.Leaves{StartIndex: 5, EndIndex: 5}); err == nil {
		t.Errorf("request for empty range not rejected with an error")
	}
	if leaves, err := client.GetLeaves(context.Background(), requests.Leaves{StartIndex: 5, EndIndex: 10}); err != nil {
		t.Errorf("request for 5:10 range failed: %v", err)
	} else if got, want := len(leaves), 2; got != want {
		t.Errorf("unexpected # leaves, got %d, want %d", got, want)
	}
}

func TestAddLeaf(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		gomock.All(
			postRequestTo("http://example.org/api/add-leaf"),
			withHeader("Sigsum-Token", "foo.example.com 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))).Return(
		newResponse(http.StatusAccepted, ""), nil)
	roundTripper.EXPECT().RoundTrip(
		gomock.All(
			postRequestTo("http://example.org/api/add-leaf"),
			withHeader("Sigsum-Token", "foo.example.com 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))).Return(
		newResponse(http.StatusOK, ""), nil)

	if persisted, err := client.AddLeaf(
		context.Background(), requests.Leaf{},
		&token.SubmitHeader{Domain: "foo.example.com"}); err != nil {
		t.Errorf("unexpected error for first AddLeaf request: %v", err)
	} else if persisted {
		t.Errorf("unexpected persisted response for first AddLeaf request")
	}
	if persisted, err := client.AddLeaf(
		context.Background(), requests.Leaf{},
		&token.SubmitHeader{Domain: "foo.example.com"}); err != nil {
		t.Errorf("unexpected error for second AddLeaf request: %v", err)
	} else if !persisted {
		t.Errorf("missing persisted response for second  AddLeaf request")
	}
}

func TestAddCheckpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		postRequestTo("http://example.org/api/add-checkpoint")).Return(
		newResponse(http.StatusOK, "\u2014 witness.example.com/w1 jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZqhf5nNo0xUe+mbIUBkBIfZ+qnA==\n"), nil)

	if cosignatures, err := client.AddCheckpoint(context.Background(), requests.AddCheckpoint{}); err != nil {
		t.Errorf("unexpected error for AddCheckpoint request: %v", err)
	} else if got, want := len(cosignatures), 1; got != want {
		t.Errorf("unexpected # cosignatures, got %d, want %d", got, want)
	} else if got, want := cosignatures[0].Timestamp, uint64(0x641850cb); got != want {
		t.Errorf("unexpected cosignature timestamp, got %d, want %d", got, want)
	}
}

func TestProcessConflictResponse(t *testing.T) {
	for _, table := range []struct {
		contentType string
		body        string
		oldSize     int // -1 if none expected
	}{
		{"text/plain", "10", -1},
		{"text/x.tlog.size", "", -1},
		{"text/x.tlog.size", "0\n", 0},
		{"text/x.tlog.size", "50\n", 50},
		{"text/x.tlog.size", "50", -1},
		{"text/x.tlog.size", "050\n", -1},
		{"text/x.tlog.size; charset=utf8", "51\n", -1},
	} {
		rsp := http.Response{}
		rsp.Header = make(http.Header)
		rsp.Header.Set("content-type", table.contentType)
		rsp.Body = io.NopCloser(bytes.NewBufferString(table.body))

		err := processConflictResponse(&rsp)
		oldSize, ok := api.ErrorConflictOldSize(err)
		if table.oldSize >= 0 {
			if !ok {
				t.Errorf("missing old size: want %d, err %v", table.oldSize, err)
			} else if got, want := oldSize, uint64(table.oldSize); got != want {
				t.Errorf("unexpected old size: got %d, want %d, err %v", got, want, err)
			}
		} else if ok {
			t.Errorf("unexpected old size: got %d, err %v", oldSize, err)
		}
	}
}

func TestThatErrorsIncludeURL(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	roundTripper := mocks.NewMockRoundTripper(ctrl)
	client := New(newTestConfig(roundTripper))

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-tree-head")).Return(
		nil, fmt.Errorf("mock error"))
	_, err := client.GetTreeHead(context.Background())

	if err == nil {
		t.Fatal("request error not propagated")
	}
	t.Logf("expected error: %v", err)
	if got, want := err.Error(), "http://example.org/api/get-tree-head"; !strings.Contains(got, want) {
		t.Errorf("got error message %q, without wanted substring %q", got, want)
	}

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-tree-head")).Return(
		newResponse(http.StatusNotFound, "mock 404 error"), nil)
	_, err = client.GetTreeHead(context.Background())

	if err == nil {
		t.Fatal("404 error not propagated")
	}
	t.Logf("expected error: %v", err)
	if got, want := err.Error(), "http://example.org/api/get-tree-head"; !strings.Contains(got, want) {
		t.Errorf("got error message %q, without wanted substring %q", got, want)
	}

	roundTripper.EXPECT().RoundTrip(
		getRequestTo("http://example.org/api/get-tree-head")).Return(
		newResponse(http.StatusOK, "not a tree head"), nil)
	_, err = client.GetTreeHead(context.Background())

	if err == nil {
		t.Fatal("parsing error not propagated")
	}
	t.Logf("expected error: %v", err)
	if got, want := err.Error(), "http://example.org/api/get-tree-head"; !strings.Contains(got, want) {
		t.Errorf("got error message %q, without wanted substring %q", got, want)
	}
}
