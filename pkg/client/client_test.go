package client

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"sigsum.org/sigsum-go/pkg/api"
)

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
