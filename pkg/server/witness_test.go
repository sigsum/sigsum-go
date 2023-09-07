package server

import (
	"bytes"
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
	"sigsum.org/sigsum-go/pkg/types"
)

func TestGetTreeSize(t *testing.T) {
	hash := crypto.Hash{0, 1, 2}
	for _, table := range []struct {
		url    string
		status int
		err    error
		size   uint64
	}{
		{url: fmt.Sprintf("/foo/get-tree-size/%x", hash), status: 200, size: 500},
		{url: fmt.Sprintf("/foo/get-tree-size/%x", hash), status: 403, err: api.ErrForbidden},
		{url: "/foo/get-tree-size/aabb", status: 400},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			witness := mocks.NewMockWitnessClient(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewWitness(&config, witness)

			if table.status != 400 {
				witness.EXPECT().GetTreeSize(gomock.Any(), requests.GetTreeSize{KeyHash: hash}).Return(table.size, table.err)
			}
			result, body := queryServer(t, server, http.MethodGet, table.url, "")
			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
			}
			if table.status != 200 {
				return
			}
			if got, want := body, fmt.Sprintf("size=%d", table.size); got != want {
				t.Errorf("Unexpected size for %q, got %q, want %q", table.url, got, want)
			}
		}()
	}
}

func writeFuncToString(t *testing.T, f func(w io.Writer) error) string {
	t.Helper()
	var buf bytes.Buffer
	if err := f(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestAddTreeHead(t *testing.T) {
	req := requests.AddTreeHead{
		KeyHash: crypto.Hash{1, 2, 3},
		TreeHead: types.SignedTreeHead{
			TreeHead:  types.TreeHead{Size: 5, RootHash: crypto.Hash{4, 5, 6}},
			Signature: crypto.Signature{7, 8, 9},
		},
		OldSize: 3,
		Proof:   types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{10, 11, 12}}},
	}
	cs := types.Cosignature{
		KeyHash:   crypto.Hash{13, 14, 15},
		Timestamp: 11111,
		Signature: crypto.Signature{16, 17, 18},
	}

	for _, table := range []struct {
		url    string
		status int
		err    error
		hook   func(*requests.AddTreeHead)
	}{
		{url: "/foo/add-tree-head", status: 200},
		{url: "/foo/add-tree-head/", status: 404},
		{url: "/foo/add-tree-head", status: 403, err: api.ErrForbidden},
		{url: "/foo/add-tree-head", status: 409, err: api.ErrConflict},
		{url: "/foo/add-tree-head", status: 400,
			hook: func(req *requests.AddTreeHead) {
				req.OldSize = 6
			},
		},
	} {
		func(req requests.AddTreeHead) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			witness := mocks.NewMockWitnessClient(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewWitness(&config, witness)

			if table.hook != nil {
				table.hook(&req)
			} else if table.status != 404 {
				witness.EXPECT().AddTreeHead(gomock.Any(), req).Return(cs, table.err)
			}
			result, body := queryServer(t, server, http.MethodPost, table.url, writeFuncToString(t, req.ToASCII))

			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
			}
			if table.status != 200 {
				return
			}
			if got, want := body, writeFuncToString(t, cs.ToASCII); got != want {
				t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
			}
		}(req)
	}
}
