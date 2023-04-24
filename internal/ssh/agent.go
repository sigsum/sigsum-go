package ssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
)

const (
	sshAgentEnv          = "SSH_AUTH_SOCK"
	sshAgentFailure      = 5
	sshAgentSignRequest  = 13
	sshAgentSignResponse = 14
)

type Connection struct {
	conn io.ReadWriter
}

type Signer struct {
	publicKey crypto.PublicKey
	conn      *Connection
}

func ConnectTo(sockName string) (*Connection, error) {
	conn, err := net.Dial("unix", sockName)
	return &Connection{conn: conn}, err
}

func Connect() (*Connection, error) {
	if sockName := os.Getenv(sshAgentEnv); len(sockName) > 0 {
		return ConnectTo(sockName)
	}
	return nil, fmt.Errorf("no ssh-agent available")
}

func (c *Connection) request(msg []byte) ([]byte, error) {
	request := serializeString(msg)
	_, err := c.conn.Write(request)
	if err != nil {
		return nil, err
	}
	// Read response length.
	lenBuf := make([]byte, 4)
	_, err = io.ReadFull(c.conn, lenBuf)
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length == 0 || length > 1000 {
		return nil, fmt.Errorf("read from agent gave unexpected length: %d", length)
	}
	buffer := make([]byte, length)
	_, err = io.ReadFull(c.conn, buffer)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

func (c Connection) SignEd25519(publicKey *crypto.PublicKey, msg []byte) (crypto.Signature, error) {
	buffer, err := c.request(bytes.Join([][]byte{
		[]byte{sshAgentSignRequest},
		serializeString(serializePublicEd25519(publicKey)),
		serializeString(msg),
		serializeUint32(0), // flags
	}, nil))
	if err != nil {
		return crypto.Signature{}, err
	}

	switch msgType, body := buffer[0], buffer[1:]; msgType {
	case sshAgentFailure:
		return crypto.Signature{}, fmt.Errorf("ssh-agent refused signature request")
	case sshAgentSignResponse:
		return parseSignature(body)
	default:
		return crypto.Signature{}, fmt.Errorf("unexpected ssh-agent response, type %d", msgType)
	}
}

func (c Connection) NewSigner(publicKey *crypto.PublicKey) (*Signer, error) {
	// TODO: Use SSH_AGENTC_REQUEST_IDENIFIER to list public keys,
	// and fail if given key is not on the list.
	return &Signer{publicKey: *publicKey, conn: &c}, nil
}

func (s *Signer) Sign(message []byte) (crypto.Signature, error) {
	return s.conn.SignEd25519(&s.publicKey, message)
}

func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

func parseSignature(blob []byte) (crypto.Signature, error) {
	signature := skipPrefix(blob, bytes.Join([][]byte{
		serializeUint32(83), // length of signature
		serializeString("ssh-ed25519"),
		serializeUint32(crypto.SignatureSize)}, nil))
	if signature == nil {
		return crypto.Signature{}, fmt.Errorf("invalid signature blob")
	}
	if len(signature) != crypto.SignatureSize {
		return crypto.Signature{}, fmt.Errorf("bad signature length: %d", len(signature))
	}
	var ret crypto.Signature
	copy(ret[:], signature)
	return ret, nil
}
