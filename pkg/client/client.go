// The client package implements a low-level client for sigsum's http
// api. It is aware of the log's public key, and verifies the log's
// own tree head signatures, but verifying appropriate witness
// cosignatures (depending on policy) is out of scope.

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type Client interface {
	GetNextTreeHead(context.Context) (types.SignedTreeHead, error)
	GetTreeHead(context.Context) (types.CosignedTreeHead, error)
	GetInclusionProof(context.Context, requests.InclusionProof) (types.InclusionProof, error)
	GetConsistencyProof(context.Context, requests.ConsistencyProof) (types.ConsistencyProof, error)
	GetLeaves(context.Context, requests.Leaves) ([]types.Leaf, error)

	AddLeaf(context.Context, requests.Leaf) (bool, error)
	AddCosignature(context.Context, types.Cosignature) error
}

var (
	HttpNotFound = errors.New("404 Not Found")
	HttpAccepted = errors.New("202 Accepted")
)

type Config struct {
	UserAgent string
	LogURL    string
}

func New(cfg Config) Client {
	return &client{
		Config: cfg,
		Client: http.Client{},
	}
}

type client struct {
	Config
	http.Client
}

func (cli *client) GetNextTreeHead(ctx context.Context) (sth types.SignedTreeHead, err error) {
	body, err := cli.get(ctx, types.EndpointGetNextTreeHead.Path(cli.LogURL))
	if err != nil {
		return sth, err
	}
	if err := sth.FromASCII(bytes.NewBuffer(body)); err != nil {
		return sth, fmt.Errorf("parse: %w", err)
	}

	return sth, nil
}

func (cli *client) GetTreeHead(ctx context.Context) (cth types.CosignedTreeHead, err error) {
	body, err := cli.get(ctx, types.EndpointGetTreeHead.Path(cli.LogURL))
	if err != nil {
		return cth, err
	}
	if err := cth.FromASCII(bytes.NewBuffer(body)); err != nil {
		return cth, fmt.Errorf("parse: %w", err)
	}

	return cth, nil
}

func (cli *client) GetInclusionProof(ctx context.Context, req requests.InclusionProof) (types.InclusionProof, error) {
	body, err := cli.get(ctx, req.ToURL(types.EndpointGetInclusionProof.Path(cli.LogURL)))
	if err != nil {
		return types.InclusionProof{}, err
	}
	var proof types.InclusionProof
	if err := proof.FromASCII(bytes.NewBuffer(body), req.Size); err != nil {
		return proof, fmt.Errorf("parse: %w", err)
	}
	return proof, err
}

func (cli *client) GetConsistencyProof(ctx context.Context, req requests.ConsistencyProof) (proof types.ConsistencyProof, err error) {
	body, err := cli.get(ctx, req.ToURL(types.EndpointGetConsistencyProof.Path(cli.LogURL)))
	if err != nil {
		return proof, err
	}
	if err := proof.FromASCII(bytes.NewBuffer(body)); err != nil {
		return proof, fmt.Errorf("parse: %w", err)
	}
	return proof, nil
}

func (cli *client) GetLeaves(ctx context.Context, req requests.Leaves) ([]types.Leaf, error) {
	body, err := cli.get(ctx, req.ToURL(types.EndpointGetLeaves.Path(cli.LogURL)))
	if err != nil {
		return nil, err
	}
	leaves, err := types.LeavesFromASCII(bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return leaves, nil
}

func (cli *client) AddLeaf(ctx context.Context, req requests.Leaf) (bool, error) {
	buf := bytes.Buffer{}
	req.ToASCII(&buf)
	if _, err := cli.post(ctx, types.EndpointAddLeaf.Path(cli.LogURL), &buf); err != nil {
		if errors.Is(err, HttpAccepted) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (cli *client) AddCosignature(ctx context.Context, req types.Cosignature) error {
	return fmt.Errorf("TODO")
}

func (cli *client) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return cli.do(req)
}

func (cli *client) post(ctx context.Context, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	return cli.do(req)
}

func (cli *client) do(req *http.Request) ([]byte, error) {
	// TODO: redirects, see go doc http.Client.CheckRedirect
	req.Header.Set("User-Agent", cli.UserAgent)

	rsp, err := cli.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer rsp.Body.Close()

	b, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("status code %d, no server response: %w",
			rsp.StatusCode, err)
	}
	switch rsp.StatusCode {
	case http.StatusNotFound:
		return nil, HttpNotFound
	case http.StatusAccepted:
		return nil, HttpAccepted
	case http.StatusOK:
		return b, nil
	default:
		return nil, fmt.Errorf("status code %d, server: %q",
			rsp.StatusCode, b)
	}
}
