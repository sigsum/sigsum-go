package server

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestGetTreeHead(t *testing.T) {
	cth := types.CosignedTreeHead{
		SignedTreeHead: types.SignedTreeHead{
			TreeHead: types.TreeHead{
				Size:     3,
				RootHash: crypto.Hash{1},
			},
			Signature: crypto.Signature{2},
		},
		Cosignatures: []types.Cosignature{
			types.Cosignature{
				KeyHash:   crypto.Hash{3},
				Timestamp: 17,
				Signature: crypto.Signature{4},
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	log := mocks.NewMockLog(ctrl)

	config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
	server := NewLog(&config, log)

	log.EXPECT().GetTreeHead(gomock.Any()).Return(cth, nil)

	result, body := queryServer(t, server, http.MethodGet, "/foo/get-tree-head", "")
	if got, want := result.StatusCode, 200; got != want {
		t.Errorf("Unexpected status code, got %d, want %d", got, want)
		return
	}
	if got, want := body, writeFuncToString(t, cth.ToASCII); got != want {
		t.Errorf("Unexpected tree head, got %v, want %v", got, want)
	}
}

func TestGetInclusionProof(t *testing.T) {
	req := requests.InclusionProof{
		Size: 2,
		LeafHash: crypto.Hash{
			170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
			170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
		},
	}
	proof := types.InclusionProof{
		LeafIndex: 1,
		Path:      []crypto.Hash{crypto.Hash{2}},
	}

	for _, table := range []struct {
		url    string
		req    *requests.InclusionProof
		rsp    types.InclusionProof
		status int
		err    error
	}{
		{url: "/foo/get-inclusion-proof", status: 301},
		{url: "/foo/get-inclusion-proof/", status: 400},
		{url: "/foo/get-inclusion-proof/x", status: 400},
		{url: "/foo/get-inclusion-proof/2/x", status: 400},
		{url: "/foo/get-inclusion-proof/2/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			req:    &req,
			rsp:    proof,
			status: 200,
		},
		{url: "/foo/get-inclusion-proof/2/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			req:    &req,
			rsp:    proof,
			status: 404,
			err:    api.ErrNotFound,
		},
		{url: "/foo/get-inclusion-proof/0/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", status: 400},
		{url: "/foo/get-inclusion-proof/1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", status: 400},
		{url: "/foo/get-inclusion-proof/2/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/b", status: 400},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			log := mocks.NewMockLog(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewLog(&config, log)

			if table.req != nil {
				log.EXPECT().GetInclusionProof(gomock.Any(), *table.req).Return(table.rsp, table.err)
			}
			result, body := queryServer(t, server, http.MethodGet, table.url, "")

			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
			}
			if table.status != 200 {
				return
			}
			if got, want := body, writeFuncToString(t, proof.ToASCII); got != want {
				t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
			}
		}()
	}
}

func TestGetConsistencyProof(t *testing.T) {
	req := requests.ConsistencyProof{
		OldSize: 2,
		NewSize: 5,
	}

	proof := types.ConsistencyProof{
		Path: []crypto.Hash{crypto.Hash{2}},
	}

	for _, table := range []struct {
		url    string
		req    *requests.ConsistencyProof
		rsp    types.ConsistencyProof
		status int
		err    error
	}{
		{url: "/foo/get-consistency-proof", status: 301},
		{url: "/foo/get-consistency-proof/", status: 400},
		{url: "/foo/get-consistency-proof/x", status: 400},
		{url: "/foo/get-consistency-proof/2/x", status: 400},
		{url: "/foo/get-consistency-proof/2/5",
			req:    &req,
			rsp:    proof,
			status: 200,
		},
		{url: "/foo/get-consistency-proof/2/5",
			req:    &req,
			rsp:    proof,
			status: 403, // Arbitrary error
			err:    api.ErrForbidden,
		},
		{url: "/foo/get-consistency-proof/2/2", status: 400},
		{url: "/foo/get-consistency-proof/0/2", status: 400},
		{url: "/foo/get-consistency-proof/2/1", status: 400},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			log := mocks.NewMockLog(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewLog(&config, log)

			if table.req != nil {
				log.EXPECT().GetConsistencyProof(gomock.Any(), *table.req).Return(table.rsp, table.err)
			}
			result, body := queryServer(t, server, http.MethodGet, table.url, "")

			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
			}
			if table.status != 200 {
				return
			}
			if got, want := body, writeFuncToString(t, proof.ToASCII); got != want {
				t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
			}
		}()
	}
}

func TestGetLeaves(t *testing.T) {
	req := requests.Leaves{StartIndex: 2, EndIndex: 5}

	for _, table := range []struct {
		url    string
		req    *requests.Leaves
		rsp    []types.Leaf
		status int
		err    error
	}{
		{url: "/foo/get-leaves", status: 301},
		{url: "/foo/get-leaves/", status: 400},
		{url: "/foo/get-leaves/x", status: 400},
		{url: "/foo/get-leaves/2/x", status: 400},
		{url: "/foo/get-leaves/2/5",
			req:    &req,
			rsp:    make([]types.Leaf, 3),
			status: 200,
		},
		{url: "/foo/get-leaves/2/5",
			req:    &req,
			rsp:    make([]types.Leaf, 4),
			status: 500,
		},
		{url: "/foo/get-leaves/2/5",
			req:    &req,
			status: 500,
		},
		{url: "/foo/get-leaves/2/5",
			req:    &req,
			rsp:    make([]types.Leaf, 3),
			status: 403, // Arbitrary error
			err:    api.ErrForbidden,
		},
		{url: "/foo/get-leaves/2/2", status: 400},
		{url: "/foo/get-leaves/2/1", status: 400},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			log := mocks.NewMockLog(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewLog(&config, log)

			if table.req != nil {
				log.EXPECT().GetLeaves(gomock.Any(), *table.req).Return(table.rsp, table.err)
			}
			result, body := queryServer(t, server, http.MethodGet, table.url, "")

			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
			}
			if table.status != 200 {
				return
			}
			if got, want := body, writeFuncToString(t, func(w io.Writer) error {
				return types.LeavesToASCII(w, table.rsp)
			}); got != want {
				t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
			}
		}()
	}
}

// Matches a pointer if both are nil, or point to equal objects.
type ptrMatcher[T comparable] struct {
	ptr *T
}

func (m ptrMatcher[T]) Matches(x any) bool {
	if ptr, ok := x.(*T); ok {
		if ptr == nil {
			return m.ptr == nil
		}
		return m.ptr != nil && *m.ptr == *ptr
	}
	return false
}

func (m ptrMatcher[T]) String() string {
	if m.ptr == nil {
		var zero T
		return fmt.Sprintf("nil ptr to %T", zero)
	}
	return fmt.Sprintf("ptr to %#v", *m.ptr)
}

func TestAddLeaf(t *testing.T) {
	req := requests.Leaf{
		Message:   crypto.Hash{1},
		Signature: crypto.Signature{2},
		PublicKey: crypto.PublicKey{3},
	}

	tokenSignature, err := crypto.SignatureFromHex(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("internal test error: %v", err)
	}
	for _, table := range []struct {
		desc         string
		url          string
		asciiHeader  string
		submitHeader *token.SubmitHeader

		exp    bool
		rsp    bool
		status int
		err    error
	}{
		{desc: "accepted", exp: true, rsp: false, status: 202},
		{desc: "success", exp: true, rsp: true, status: 200},
		{desc: "bad url", url: "/foo/add-leaf/", rsp: true, status: 404},
		{desc: "forbidden", err: api.ErrForbidden, status: 403},
		{desc: "rate limit", err: api.ErrTooManyRequests, status: 429},
		{
			desc:         "success with submit token",
			exp:          true,
			asciiHeader:  "foo.example.org aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			submitHeader: &token.SubmitHeader{Domain: "foo.example.org", Token: tokenSignature},
			status:       202,
		},
		{
			desc:         "forbidden with submit token",
			asciiHeader:  "foo.example.org aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			submitHeader: &token.SubmitHeader{Domain: "foo.example.org", Token: tokenSignature},
			err:          api.ErrForbidden,
			status:       403,
		},
		{
			desc:         "rate limit with with submit token",
			asciiHeader:  "foo.example.org aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			submitHeader: &token.SubmitHeader{Domain: "foo.example.org", Token: tokenSignature},
			err:          api.ErrTooManyRequests,
			status:       429,
		},
		{
			desc:        "invalid submit token",
			asciiHeader: "foo.example.org aaaaaxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			status:      400,
		},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			log := mocks.NewMockLog(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewLog(&config, log)

			if table.exp || table.err != nil {
				log.EXPECT().AddLeaf(gomock.Any(), req,
					ptrMatcher[token.SubmitHeader]{table.submitHeader}).Return(table.rsp, table.err)
			}
			url := "/foo/add-leaf"
			if table.url != "" {
				url = table.url
			}
			result, body := queryServerHook(t, server, http.MethodPost,
				url, writeFuncToString(t, req.ToASCII),
				func(req *http.Request) *http.Request {
					if table.asciiHeader != "" {
						req.Header.Set("sigsum-token", table.asciiHeader)
					}
					return req
				})
			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("%s: Unexpected status code for, got %d, want %d", table.desc, got, want)
			}
			if table.status != 200 {
				t.Logf("%s: response body: %q", table.desc, body)
				return
			}
			if body != "" {
				t.Errorf("%s: Unexpected response body: %q", table.desc, body)
			}
		}()
	}
}
