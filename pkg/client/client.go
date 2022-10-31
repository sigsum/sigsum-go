package client

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type Client interface {
	GetUnsignedTreeHead(context.Context) (types.TreeHead, error)
	GetToCosignTreeHead(context.Context) (types.SignedTreeHead, error)
	GetCosignedTreeHead(context.Context) (types.CosignedTreeHead, error)
	GetInclusionProof(context.Context, requests.InclusionProof) (types.InclusionProof, error)
	GetConsistencyProof(context.Context, requests.ConsistencyProof) (types.ConsistencyProof, error)
	GetLeaves(context.Context, requests.Leaves) (types.Leaves, error)

	AddLeaf(context.Context, requests.Leaf) (bool, error)
	AddCosignature(context.Context, requests.Cosignature) error

	Initiated() bool
}

type Config struct {
	UserAgent string
	LogURL    string
	LogPub    crypto.PublicKey
	// TODO: witness public keys + policy
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

func (cli *client) Initiated() bool {
	return cli.LogURL != ""
}

func (cli *client) GetUnsignedTreeHead(ctx context.Context) (th types.TreeHead, err error) {
	body, _, err := cli.get(ctx, types.EndpointGetTreeHeadUnsigned.Path(cli.LogURL))
	if err != nil {
		return th, fmt.Errorf("get: %w", err)
	}
	if err := th.FromASCII(bytes.NewBuffer(body)); err != nil {
		return th, fmt.Errorf("parse: %w", err)
	}

	return th, nil
}

func (cli *client) GetToCosignTreeHead(ctx context.Context) (sth types.SignedTreeHead, err error) {
	body, _, err := cli.get(ctx, types.EndpointGetTreeHeadToCosign.Path(cli.LogURL))
	if err != nil {
		return sth, fmt.Errorf("get: %w", err)
	}
	if err := sth.FromASCII(bytes.NewBuffer(body)); err != nil {
		return sth, fmt.Errorf("parse: %w", err)
	}
	if ok := sth.Verify(&cli.LogPub); !ok {
		return sth, fmt.Errorf("invalid log signature")
	}

	return sth, nil
}

func (cli *client) GetCosignedTreeHead(ctx context.Context) (cth types.CosignedTreeHead, err error) {
	body, _, err := cli.get(ctx, types.EndpointGetTreeHeadCosigned.Path(cli.LogURL))
	if err != nil {
		return cth, fmt.Errorf("get: %w", err)
	}
	if err := cth.FromASCII(bytes.NewBuffer(body)); err != nil {
		return cth, fmt.Errorf("parse: %w", err)
	}
	if ok := cth.SignedTreeHead.Verify(&cli.LogPub); !ok {
		return cth, fmt.Errorf("invalid log signature")
	}
	// TODO: verify cosignatures based on policy
	return cth, nil
}

func (cli *client) GetInclusionProof(ctx context.Context, req requests.InclusionProof) (proof types.InclusionProof, err error) {
	return proof, fmt.Errorf("TODO")
}

func (cli *client) GetConsistencyProof(ctx context.Context, req requests.ConsistencyProof) (proof types.ConsistencyProof, err error) {
	body, _, err := cli.get(ctx, req.ToURL(types.EndpointGetConsistencyProof.Path(cli.LogURL)))
	if err != nil {
		return proof, fmt.Errorf("get: %w", err)
	}
	if err := proof.FromASCII(bytes.NewBuffer(body), req.OldSize, req.NewSize); err != nil {
		return proof, fmt.Errorf("parse: %w", err)
	}
	return proof, nil
}

func (cli *client) GetLeaves(ctx context.Context, req requests.Leaves) (leaves types.Leaves, err error) {
	body, _, err := cli.get(ctx, req.ToURL(types.EndpointGetLeaves.Path(cli.LogURL)))
	if err != nil {
		return leaves, fmt.Errorf("get: %w", err)
	}
	if err := leaves.FromASCII(bytes.NewBuffer(body)); err != nil {
		return leaves, fmt.Errorf("parse: %w", err)
	}
	return leaves, nil
}

func (cli *client) AddLeaf(ctx context.Context, req requests.Leaf) (persisted bool, err error) {
	return false, fmt.Errorf("TODO")
}

func (cli *client) AddCosignature(ctx context.Context, req requests.Cosignature) error {
	return fmt.Errorf("TODO")
}

func (cli *client) get(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, -1, err
	}
	return cli.do(ctx, req)
}

func (cli *client) post(ctx context.Context, url string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, -1, err
	}
	return cli.do(ctx, req)
}

func (cli *client) do(ctx context.Context, req *http.Request) ([]byte, int, error) {
	// TODO: redirects, see go doc http.Client.CheckRedirect
	// TODO: use ctx or remove it -- the context is already set on req so it seems unneccesary
	req.Header.Set("User-Agent", cli.UserAgent)

	var rsp *http.Response
	var err error
	for wait := 1; wait < 10; wait *= 2 {
		log.Debug("trying %v", req.URL)
		if rsp, err = cli.Client.Do(req); err == nil {
			break
		}
		sleep := time.Duration(wait) * time.Second
		log.Debug("retrying in %v", sleep)
		time.Sleep(sleep)
	}
	if err != nil {
		return nil, -1, fmt.Errorf("send request: %w", err)
	}
	defer rsp.Body.Close()
	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, rsp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	if low, high := 200, 299; rsp.StatusCode < low || rsp.StatusCode > high {
		err = fmt.Errorf("not 2XX status code: %d", rsp.StatusCode)
	}
	return b, rsp.StatusCode, err
}
