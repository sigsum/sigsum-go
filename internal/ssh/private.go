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

const pemPrivateKeyTag = "OPENSSH PRIVATE KEY"

var NoPEMError = errors.New("not a PEM file")

var opensshPrivateKeyPrefix = bytes.Join([][]byte{
	[]byte("openssh-key-v1"), []byte{0},
	// cipher "none", kdf "none"
	serializeString("none"), serializeString("none"),
	serializeUint32(0), serializeUint32(1), // empty kdf, and #keys = 1
}, nil)

// Deterministic variant with nonce input, for unit testing.
func writePrivateKeyFile(w io.Writer, signer *crypto.Ed25519Signer, nonce [4]byte) error {
	pub := signer.Public()
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
		[]byte{1, 2, 3, 4, 5},
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

func ParsePrivateKeyFile(ascii []byte) (crypto.PublicKey, *crypto.Ed25519Signer, error) {
	parseBlob := func(blob []byte) (crypto.PublicKey, *crypto.Ed25519Signer, error) {
		blob = skipPrefix(blob, opensshPrivateKeyPrefix)
		if blob == nil {
			return crypto.PublicKey{}, nil, fmt.Errorf("invalid or encrypted private key")
		}
		publicKeyBlob, blob := parseString(blob)
		if blob == nil {
			return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key, pubkey missing")
		}
		pub, err := parsePublicEd25519(publicKeyBlob)
		if err != nil {
			return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key, pubkey invalid: %w", err)
		}
		length, blob := parseUint32(blob)
		if blob == nil || int64(length) != int64(len(blob)) ||
			length%8 != 0 {
			return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key")
		}
		n1, blob := parseUint32(blob)
		n2, blob := parseUint32(blob)
		if blob == nil || n1 != n2 {
			return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key, bad nonce")
		}
		blob = skipPrefix(blob, publicKeyBlob)
		if blob == nil {
			return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key, inconsistent public key")
		}
		keys, blob := parseString(blob)
		if blob == nil {
			return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key, private key missing")
		}
		// The keys blob consists of the 32-byte private key +
		// 32 byte public key.
		if len(keys) != 64 {
			return crypto.PublicKey{}, nil, fmt.Errorf("unexpected private key size: %d", len(keys))
		}
		if !bytes.Equal(pub[:], keys[32:]) {
			return crypto.PublicKey{}, nil, fmt.Errorf("inconsistent public key")
		}
		var privateKey crypto.PrivateKey
		copy(privateKey[:], keys[:32])
		signer := crypto.NewEd25519Signer(&privateKey)
		if signer.Public() != pub {
			return crypto.PublicKey{}, nil, fmt.Errorf("inconsistent private key")
		}

		return pub, signer, nil
	}
	block, _ := pem.Decode(ascii)
	if block == nil {
		return crypto.PublicKey{}, nil, NoPEMError
	}
	if block.Type != pemPrivateKeyTag {
		return crypto.PublicKey{}, nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	return parseBlob(block.Bytes)
}
