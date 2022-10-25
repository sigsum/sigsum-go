package ssh

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const (
	sshAgentEnv          = "SSH_AUTH_SOCK"
	sshAgentFailure      = 5
	sshAgentSignRequest  = 13
	sshAgentSignResponse = 14
)

type Connection struct {
	conn net.Conn
}

type Signer struct {
	publicKey ed25519.PublicKey
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
	writeCount, err := c.conn.Write(request)
	if err != nil {
		return nil, err
	}
	if writeCount != len(request) {
		// TODO: How to access errno?
		return nil, fmt.Errorf("write to agent failed, with short byte count: %d", writeCount)
	}
	// Read response length.
	lenBuf := make([]byte, 4)
	readCount, err := c.conn.Read(lenBuf)
	if err != nil {
		return nil, err
	}
	if readCount != len(lenBuf) {
		// TODO: How to access errno?
		return nil, fmt.Errorf("read from agent failed, no length field, short byte count: %d", readCount)
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length == 0 || length > 1000 {
		return nil, fmt.Errorf("read from agent gave unexpected length: %d", length)
	}
	buffer := make([]byte, length)
	readCount, err = c.conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	if readCount != len(buffer) {
		// TODO: How to access errno?
		return nil, fmt.Errorf("read from agent failed, short byte count: %d", readCount)
	}
	return buffer, nil
}

func (c Connection) SignEd25519(publicKey ed25519.PublicKey, msg []byte) ([]byte, error) {
	buffer, err := c.request(bytes.Join([][]byte{
		[]byte{sshAgentSignRequest},
		serializeString(serializePublicEd25519(publicKey)),
		serializeString(msg),
		serializeUint32(0), // flags
	}, nil))
	if err != nil {
		return nil, err
	}

	switch msgType, body := buffer[0], buffer[1:]; msgType {
	case sshAgentFailure:
		return nil, fmt.Errorf("ssh-agent refused signature request")
	case sshAgentSignResponse:
		return parseSignature(body)
	default:
		return nil, fmt.Errorf("unexpected ssh-agent response, type %d", msgType)
	}
}

func (c Connection) NewSigner(publicKey ed25519.PublicKey) (*Signer, error) {
	// TODO: Use SSH_AGENTC_REQUEST_IDENIFIER to list public keys,
	// and fail if given key is not on the list.
	return &Signer{publicKey: publicKey, conn: &c}, nil
}

func (s *Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.conn.SignEd25519(s.publicKey, message)
}

func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}
