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
	"sigsum.org/sigsum-go/pkg/checkpoint"
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
			witness := mocks.NewMockWitness(ctrl)

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
			if got, want := body, fmt.Sprintf("size=%d\n", table.size); got != want {
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
	keyHash := crypto.Hash{13, 14, 15}
	cs := types.Cosignature{
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
			witness := mocks.NewMockWitness(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewWitness(&config, witness)

			if table.hook != nil {
				table.hook(&req)
			} else if table.status != 404 {
				witness.EXPECT().AddTreeHead(gomock.Any(), req).Return(keyHash, cs, table.err)
			}
			result, body := queryServer(t, server, http.MethodPost, table.url, writeFuncToString(t, req.ToASCII))

			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d, want %d", table.url, got, want)
			}
			if table.status != 200 {
				return
			}

			var buf bytes.Buffer
			if err := cs.ToASCII(&buf, &keyHash); err != nil {
				t.Fatal(err)
			}
			if got, want := body, buf.String(); got != want {
				t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
			}
		}(req)
	}
}

func TestAddCheckpoint(t *testing.T) {
	req := requests.AddCheckpoint{
		OldSize: 3,
		Proof:   types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{10, 11, 12}}},
		Checkpoint: checkpoint.Checkpoint{
			Origin: "example.org/log",
			SignedTreeHead: types.SignedTreeHead{
				TreeHead: types.TreeHead{
					Size:     5,
					RootHash: crypto.Hash{4, 5, 6}},
				Signature: crypto.Signature{7, 8, 9},
			},
		},
	}
	csl := checkpoint.CosignatureLine{
		KeyName: "example.org/witness",
		KeyId:   checkpoint.KeyId{0, 1, 2, 3},
		Cosignature: types.Cosignature{
			Timestamp: 11111,
			Signature: crypto.Signature{16, 17, 18},
		},
	}

	for _, table := range []struct {
		url    string
		status int
		err    error
		hook   func(*requests.AddCheckpoint)
	}{
		{url: "/foo/add-checkpoint", status: 200},
		{url: "/foo/add-checkpoint/", status: 404},
		{url: "/foo/add-checkpoint", status: 403, err: api.ErrForbidden},
		{url: "/foo/add-checkpoint", status: 409, err: api.ErrConflict.WithOldSize(3)},
		{url: "/foo/add-checkpoint", status: 400,
			hook: func(req *requests.AddCheckpoint) {
				req.OldSize = 6
			},
		},
	} {
		func(req requests.AddCheckpoint) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			witness := mocks.NewMockWitness(ctrl)

			config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
			server := NewWitness(&config, witness)

			if table.hook != nil {
				table.hook(&req)
			} else if table.status != 404 {
				witness.EXPECT().AddCheckpoint(gomock.Any(), req).Return([]checkpoint.CosignatureLine{csl}, table.err)
			}

			result, body := queryServer(t, server, http.MethodPost, table.url, writeFuncToString(t, req.ToASCII))

			if got, want := result.StatusCode, table.status; got != want {
				t.Errorf("Unexpected status code for %q, got %d %q, want %d", table.url, got, body, want)
			}
			switch table.status {
			case 200:
				if got, want := body, writeFuncToString(t, csl.ToASCII); got != want {
					t.Errorf("Unexpected response for %q, got %q, want %q", table.url, got, want)
				}
			case 409:
				if got, want := body, "3\n"; got != want {
					t.Errorf("Unexpected conflict response, got %q, want %q", got, want)
				}
			default:
			}
		}(req)
	}
}
