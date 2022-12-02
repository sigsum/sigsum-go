package ssh

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/crypto"
)

const pemSignatureTag = "SSH SIGNATURE"

var NoPEMError = errors.New("not a PEM file")

func WriteSignatureFile(w io.Writer, publicKey *crypto.PublicKey, namespace string, signature *crypto.Signature) error {
	blob := bytes.Join([][]byte{
		[]byte("SSHSIG"),
		serializeUint32(1), // version 1
		serializeString(serializePublicEd25519(publicKey)),
		serializeString([]byte(namespace)),
		serializeUint32(0), // Empty reserved string
		serializeString([]byte("sha256")),
		serializeUint32(83),
		serializeString([]byte("ssh-ed25519")),
		serializeString(signature[:]),
	}, nil)
	return pem.Encode(w, &pem.Block{Type: pemSignatureTag, Bytes: blob})
}

func parseSignatureFile(blob []byte, publicKey *crypto.PublicKey, namespace string) (crypto.Signature, error) {
	blob = skipPrefix(blob, bytes.Join([][]byte{
		[]byte("SSHSIG"),
		serializeUint32(1), // version 1
	}, nil))
	if blob == nil {
		return crypto.Signature{}, fmt.Errorf("invalid signature prefix")
	}
	blob = skipPrefixString(blob, serializePublicEd25519(publicKey))
	if blob == nil {
		return crypto.Signature{}, fmt.Errorf("signature public key not as expected")
	}
	blob = skipPrefixString(blob, []byte(namespace))
	if blob == nil {
		return crypto.Signature{}, fmt.Errorf("signature namespace not as expected")
	}
	blob = skipPrefix(blob, bytes.Join([][]byte{
		serializeUint32(0), // Empty reserved string
		serializeString([]byte("sha256")),
	}, nil))
	if blob == nil {
		return crypto.Signature{}, fmt.Errorf("signature hash not as expected")
	}
	return parseSignature(blob)
}

func ParseSignatureFile(ascii []byte, pub *crypto.PublicKey, namespace string) (crypto.Signature, error) {
	parseBlob := func(blob []byte, pub *crypto.PublicKey, namespace string) (crypto.Signature, error) {
		blob = skipPrefix(blob, bytes.Join([][]byte{
			[]byte("SSHSIG"),
			serializeUint32(1), // version 1
		}, nil))
		if blob == nil {
			return crypto.Signature{}, fmt.Errorf("invalid signature prefix")
		}
		blob = skipPrefixString(blob, serializePublicEd25519(pub))
		if blob == nil {
			return crypto.Signature{}, fmt.Errorf("signature public key not as expected")
		}
		blob = skipPrefixString(blob, []byte(namespace))
		if blob == nil {
			return crypto.Signature{}, fmt.Errorf("signature namespace not as expected")
		}
		blob = skipPrefix(blob, bytes.Join([][]byte{
			serializeUint32(0), // Empty reserved string
			serializeString([]byte("sha256")),
		}, nil))
		if blob == nil {
			return crypto.Signature{}, fmt.Errorf("signature hash not as expected")
		}
		return parseSignature(blob)
	}

	block, _ := pem.Decode(ascii)
	if block == nil {
		return crypto.Signature{}, NoPEMError
	}
	if block.Type != pemSignatureTag {
		return crypto.Signature{}, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	return parseBlob(block.Bytes, pub, namespace)
}
