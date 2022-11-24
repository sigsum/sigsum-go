package ssh

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

type mockConnection struct {
	readBuf  []byte
	writeBuf []byte
}

func (c *mockConnection) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if c.readBuf == nil {
		return 0, fmt.Errorf("mocked read error")
	}
	if len(c.readBuf) == 0 {
		return 0, io.EOF
	}
	// Return bytes only one at a time.
	buf[0] = c.readBuf[0]
	c.readBuf = c.readBuf[1:]
	return 1, nil
}

func (c *mockConnection) Write(buf []byte) (int, error) {
	if c.writeBuf == nil {
		return 0, fmt.Errorf("mocked write failure")
	}
	c.writeBuf = append(c.writeBuf, buf...)
	return len(buf), nil
}

func h(ascii string) []byte {
	s, err := hex.DecodeString(ascii)
	if err != nil {
		panic(fmt.Errorf("invalid hex %q: %v", ascii, err))
	}
	return s
}

func TestRequest(t *testing.T) {
	for _, table := range []struct {
		desc           string
		request        []byte
		expResponse    []byte // nil for expected error
		expWireRequest []byte // nil for write errors
		wireResponse   []byte
	}{
		{"empty", []byte(""), nil, h("00000000"), h("00000000")},
		{"empty body", []byte(""), []byte{5}, h("00000000"), h("0000000105")},
		{"eof length", h(""), nil, h("00000000"), h("000000")},
		{"non-empty", []byte("abc"), []byte("defg"), h("00000003616263"), h("0000000464656667")},
		{"eof data", []byte("abc"), nil, h("00000003616263"), h("0000004064656667")},
		{"write error", []byte("abc"), nil, nil, h("0000000464656667")},
		{"read error", []byte("abc"), nil, h("00000003616263"), nil},
	} {
		mockConn := mockConnection{}
		mockConn.readBuf = table.wireResponse
		if table.expWireRequest != nil {
			mockConn.writeBuf = []byte{}
		}
		c := Connection{&mockConn}
		response, err := c.request(table.request)
		if err != nil {
			if table.expResponse != nil {
				t.Errorf("%q: unexpected failure: %v", table.desc, err)
			}
		} else {
			if !bytes.Equal(mockConn.writeBuf, table.expWireRequest) {
				t.Errorf("%q: unexpected request on the wire, got %x, wanted %x",
					table.desc, mockConn.writeBuf, table.expWireRequest)
			}
			if table.expResponse == nil {
				t.Errorf("%q: unexpected success, response: %x", table.desc, response)
			} else if !bytes.Equal(response, table.expResponse) {
				t.Errorf("%q: bad response, got %x, wanted %x",
					table.desc, response, table.expResponse)
			}
		}
	}
}

func TestSignEd25519(t *testing.T) {
	privateKey := crypto.PrivateKey{17}
	signer := crypto.NewEd25519Signer(&privateKey)
	publicKey := signer.Public()

	msg := []byte("abc")
	signature, err := signer.Sign(msg)
	if err != nil {
		panic(fmt.Errorf("signing failed: %v", err))
	}

	response := serializeString(bytes.Join([][]byte{
		[]byte{sshAgentSignResponse},
		serializeString(bytes.Join([][]byte{
			serializeString([]byte("ssh-ed25519")),
			serializeString(signature[:]),
		}, nil)),
	}, nil))

	mockConn := mockConnection{readBuf: response, writeBuf: []byte{}}
	c := Connection{&mockConn}

	resp, err := c.SignEd25519(&publicKey, msg)
	if err != nil {
		t.Errorf("SignEd25519 failed: %v", err)
	} else if resp != signature {
		t.Errorf("unexpected signature, got %x, wanted %x", resp, signature)
	}
	expRequest := h("000000430d000000330000000b7373682d656432353531390000002066e0b858" +
		"e462a609e66fe71370c816d8846ff103d5499a22a7fec37fdbc424a70000000361626300000000")
	if !bytes.Equal(mockConn.writeBuf, expRequest) {
		t.Errorf("unexpected request on the wire, got %x, wanted %x",
			mockConn.writeBuf, expRequest)
	}
}

func TestSignEd25519Fail(t *testing.T) {
	// Test a couple of failure cases.
	for _, table := range []struct {
		desc         string
		wireResponse []byte
		expError     string
	}{
		{"agent failure message", h("0000000105"), "refused"},
		{"top parse failure", h("00000000"), "unexpected length"},
		{"unexpected type", h("000000010f"), "unexpected ssh-agent response"},
		// Contains algorithm "ssh-ed25518"
		{"signature parse failure", h("000000580e000000530000000b7373682d656432353531380000004084443b7c0c7fef71eaed5acd742c6cf765b4f2af4cf901adaad0b56dccbe72f42cafe3d3649a352173b7ac38a6f702050b71f5a6212c6d5a26053daca445db0a"), "invalid signature blob"},
	} {
		mockConn := mockConnection{readBuf: table.wireResponse, writeBuf: []byte{}}
		c := Connection{&mockConn}

		signature, err := c.SignEd25519(&crypto.PublicKey{}, []byte("msg"))
		if err == nil {
			t.Errorf("%q: unexpected success, got signature %x\n", table.desc, signature)
		} else if !strings.Contains(err.Error(), table.expError) {
			t.Errorf("%q: expected error containing %q, got: %v", table.desc, table.expError, err)
		}
	}
}
