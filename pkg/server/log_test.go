package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/requests"
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
		{url: "/foo/get-inclusion-proof/2/2", status: 400},
		{url: "/foo/get-inclusion-proof/0/2", status: 400},
		{url: "/foo/get-inclusion-proof/2/1", status: 400},
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

// TODO: XXX func TestGetLeaves(t *testing.T) {}, func TestAddLeaf(t *testing.T) {}
