package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// For documentation of the openssh private key format, see
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
// https://coolaj86.com/articles/the-openssh-private-key-format
//
// This implementation supports only unencrypted ed25519 keys.

const (
	pemPrivateKeyTag = "OPENSSH PRIVATE KEY"
)

var (
	ErrNotPEM = errors.New("not a PEM file")

	opensshPrivateKeyPrefix = bytes.Join([][]byte{
		[]byte("openssh-key-v1"), {0},
		// cipher "none", kdf "none"
		serializeString("none"), serializeString("none"),
		serializeUint32(0), serializeUint32(1), // empty kdf, and #keys = 1
	}, nil)
	opensshPrivateKeyPadding = []byte{1, 2, 3, 4, 5, 6, 7}
)

// Deterministic variant with nonce input, for unit testing.
func writePrivateKeyFile(w io.Writer, signer *crypto.Ed25519Signer, nonce [4]byte) error {
	pub := signer.Ed25519Public()
	priv := signer.Private()

	pubBlob := serializePublicEd25519(&pub)

	blob := bytes.Join([][]byte{
		// Prefix + first copy of public key
		opensshPrivateKeyPrefix, serializeString(pubBlob),

		// Followed by the data that could be encrypted, but isn't in our case.
		// Length of below data.
		serializeUint32(136),

		// Size of above is
		//   8 (nonce)
		//  51 (public part)
		//  68 (private part)
		//   4 (comment)
		//   5 (padding)
		// ----
		// 136 (sum)

		// Add nonce twice, presumably to check for correct decryption
		nonce[:], nonce[:],

		// Private key is public key + additional private parameters.
		pubBlob,

		// Finally, the ssh secret key, which includes the raw public
		// key once more.
		serializeUint32(64), // Length of private + public key
		priv[:],
		pub[:],
		// Empty comment.
		serializeUint32(0),
		// Padding
		{1, 2, 3, 4, 5},
	}, nil)
	return pem.Encode(w, &pem.Block{Type: pemPrivateKeyTag, Bytes: blob})
}

func WritePrivateKeyFile(w io.Writer, signer *crypto.Ed25519Signer) error {
	var nonce [4]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return err
	}

	return writePrivateKeyFile(w, signer, nonce)
}

func ParsePrivateKeyFile(ascii []byte) (crypto.Ed25519PublicKey, *crypto.Ed25519Signer, error) {
	data, err := parsePrivateKeyFile(ascii)
	if err != nil {
		return crypto.Ed25519PublicKey{}, nil, err
	}

	keys, err := parseBytes(data.privateKeyBlob, opensshPrivateKeyPadding, func(r io.Reader) (*keyPair, error) {
		return readPrivateKeyInner(r, data.publicKeyBlob)
	})
	if err != nil {
		return crypto.Ed25519PublicKey{}, nil, err
	}
	return keys.pub, keys.priv, nil
}

type privateKeyData struct {
	publicKeyBlob  []byte
	privateKeyBlob []byte
}

func parsePrivateKeyFile(ascii []byte) (*privateKeyData, error) {
	block, _ := pem.Decode(ascii)
	if block == nil {
		return nil, ErrNotPEM
	}
	if block.Type != pemPrivateKeyTag {
		return nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	return parseBytes(block.Bytes, nil, func(r io.Reader) (*privateKeyData, error) {
		if err := readSkip(r, opensshPrivateKeyPrefix); err != nil {
			return nil, err
		}
		publicKeyBlob, err := readString(r)
		if err != nil {
			return nil, fmt.Errorf("reading pubkey: %w", err)
		}
		privBlob, err := readString(r)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %v", err)
		}
		return &privateKeyData{
			publicKeyBlob:  publicKeyBlob,
			privateKeyBlob: privBlob,
		}, nil
	})
}

type keyPair struct {
	pub  crypto.Ed25519PublicKey
	priv *crypto.Ed25519Signer
}

// readPrivateKeyInner reads the inner private key data, i.e. the
// section that is potentially encrypted.
func readPrivateKeyInner(r io.Reader, publicKeyBlob []byte) (*keyPair, error) {
	publicKey, err := parseBytes(publicKeyBlob, nil, readPublicEd25519)
	if err != nil {
		return nil, err
	}
	n1, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	n2, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	if n1 != n2 {
		return nil, fmt.Errorf("wrong passphrase or invalid private key")
	}

	if err := readSkip(r, publicKeyBlob); err != nil {
		return nil, fmt.Errorf("invalid private key, inconsistent public key: %v", err)
	}
	// The keys blob consists of the private key + public key.
	keys, err := readStringOfLength(r, crypto.Ed25519PrivateKeySize+crypto.Ed25519PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, private key missing: %v", err)
	}
	if !bytes.Equal(publicKey[:], keys[crypto.Ed25519PrivateKeySize:]) {
		return nil, fmt.Errorf("inconsistent public key")
	}
	_, err = readString(r)
	if err != nil {
		return nil, fmt.Errorf("comment string missing")
	}

	priv := crypto.Ed25519PrivateKey(keys[:crypto.Ed25519PrivateKeySize])
	return &keyPair{
		pub: publicKey, priv: crypto.NewEd25519Signer(&priv),
	}, nil
}
