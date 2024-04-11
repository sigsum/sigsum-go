// The client package implements a low-level client for sigsum's http
// api. Verifying appropriate signatures and cosignatures (depending
// on policy) is out of scope.

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/requests"
	token "sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

type Config struct {
	UserAgent string
	URL       string

	// HTTPClient specifies the HTTP client to use when making requests to the log.
	// If nil, a default client is created.
	HTTPClient *http.Client
}

func (c Config) getHTTPClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{}
}

func New(cfg Config) *Client {
	return &Client{
		config: cfg,
		client: cfg.getHTTPClient(),
	}
}

type Client struct {
	config Config
	client *http.Client
}

func (cli *Client) GetSecondaryTreeHead(ctx context.Context) (sth types.SignedTreeHead, err error) {
	err = cli.get(ctx, types.EndpointGetSecondaryTreeHead.Path(cli.config.URL), sth.FromASCII)
	return
}

func (cli *Client) GetTreeHead(ctx context.Context) (cth types.CosignedTreeHead, err error) {
	err = cli.get(ctx, types.EndpointGetTreeHead.Path(cli.config.URL), cth.FromASCII)
	return
}

func (cli *Client) GetInclusionProof(ctx context.Context, req requests.InclusionProof) (proof types.InclusionProof, err error) {
	err = cli.get(ctx, req.ToURL(types.EndpointGetInclusionProof.Path(cli.config.URL)), proof.FromASCII)
	return
}

func (cli *Client) GetConsistencyProof(ctx context.Context, req requests.ConsistencyProof) (proof types.ConsistencyProof, err error) {
	err = cli.get(ctx, req.ToURL(types.EndpointGetConsistencyProof.Path(cli.config.URL)), proof.FromASCII)
	return
}

func (cli *Client) GetLeaves(ctx context.Context, req requests.Leaves) (leaves []types.Leaf, err error) {
	if req.StartIndex >= req.EndIndex {
		return nil, fmt.Errorf("invalid request, StartIndex (%d) >= EndIndex (%d)",
			req.StartIndex, req.EndIndex)
	}
	err = cli.get(ctx, req.ToURL(types.EndpointGetLeaves.Path(cli.config.URL)),
		func(r io.Reader) (err error) {
			leaves, err = types.LeavesFromASCII(r, req.StartIndex-req.EndIndex)
			return err
		})
	return
}

func (cli *Client) AddLeaf(ctx context.Context, req requests.Leaf, header *token.SubmitHeader) (bool, error) {
	buf := bytes.Buffer{}
	req.ToASCII(&buf)
	var tokenHeader *string
	if header != nil {
		s := header.ToHeader()
		tokenHeader = &s
	}
	if err := cli.post(ctx, types.EndpointAddLeaf.Path(cli.config.URL), tokenHeader, &buf, nil); err != nil {
		if errors.Is(err, api.ErrAccepted) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (cli *Client) GetTreeSize(ctx context.Context, req requests.GetTreeSize) (uint64, error) {
	var size uint64
	if err := cli.get(ctx, req.ToURL(types.EndpointGetTreeSize.Path(cli.config.URL)),
		func(body io.Reader) error {
			p := ascii.NewParser(body)
			var err error
			size, err = p.GetInt("size")
			if err != nil {
				return err
			}
			return p.GetEOF()
		}); err != nil {
		return 0, err
	}
	return size, nil
}

func (cli *Client) AddTreeHead(ctx context.Context, req requests.AddTreeHead) (types.Cosignature, error) {
	buf := bytes.Buffer{}
	req.ToASCII(&buf)
	var cs types.Cosignature
	if err := cli.post(ctx, types.EndpointAddTreeHead.Path(cli.config.URL), nil, &buf, cs.FromASCII); err != nil {
		return types.Cosignature{}, err
	}
	return cs, nil
}

func (cli *Client) get(ctx context.Context, url string,
	parseBody func(io.Reader) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return cli.do(req, parseBody)
}

func (cli *Client) post(ctx context.Context, url string, tokenHeader *string, requestBody io.Reader, parseResponse func(io.Reader) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, requestBody)
	if err != nil {
		return err
	}
	if tokenHeader != nil {
		req.Header.Add(token.HeaderName, *tokenHeader)
	}
	return cli.do(req, parseResponse)
}

func (cli *Client) do(req *http.Request, parseBody func(io.Reader) error) error {
	// TODO: redirects, see go doc http.Client.CheckRedirect
	req.Header.Set("User-Agent", cli.config.UserAgent)

	rsp, err := cli.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode == http.StatusOK && parseBody != nil {
		return parseBody(rsp.Body)
	}
	b, err := io.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("status code %d, no server response: %w",
			rsp.StatusCode, err)
	}
	if rsp.StatusCode != http.StatusOK {
		return api.NewError(rsp.StatusCode, fmt.Errorf("server: %q", b))
	}
	return nil
}
