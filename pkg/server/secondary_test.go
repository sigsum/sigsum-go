package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/mocks/mockapi"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestGetSecondaryTreeHead(t *testing.T) {
	sth := types.SignedTreeHead{
		TreeHead: types.TreeHead{
			Size:     3,
			RootHash: crypto.Hash{1},
		},
		Signature: crypto.Signature{2},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	log := mockapi.NewMockSecondary(ctrl)

	config := Config{Prefix: "foo", Timeout: 5 * time.Minute}
	server := NewSecondary(&config, log)

	log.EXPECT().GetSecondaryTreeHead(gomock.Any()).Return(sth, nil)

	result, body := queryServer(t, server, http.MethodGet, "/foo/get-secondary-tree-head", "")
	if got, want := result.StatusCode, 200; got != want {
		t.Errorf("Unexpected status code, got %d, want %d", got, want)
		return
	}
	if got, want := body, writeFuncToString(t, sth.ToASCII); got != want {
		t.Errorf("Unexpected tree head, got %v, want %v", got, want)
	}
}
