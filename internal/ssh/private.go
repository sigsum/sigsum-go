package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"

	"sigsum.org/key-mgmt/pkg/ssh"

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
	ssh.SerializeString("none"), ssh.SerializeString("none"),
	ssh.SerializeUint32(0), ssh.SerializeUint32(1), // empty kdf, and #keys = 1
}, nil)

// Deterministic variant with nonce input, for unit testing.
func writePrivateKeyFile(w io.Writer, signer *crypto.Ed25519Signer, nonce [4]byte) error {
	pub := signer.Public()
	priv := signer.Private()

	pubBlob := ssh.SerializeEd25519PublicKey(pub[:])

	blob := bytes.Join([][]byte{
		// Prefix + first copy of public key
		opensshPrivateKeyPrefix, ssh.SerializeString(pubBlob),

		// Followed by the data that could be encrypted, but isn't in our case.
		// Length of below data.
		ssh.SerializeUint32(136),

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
		ssh.SerializeUint32(64), // Length of private + public key
		priv[:],
		pub[:],
		// Empty comment.
		ssh.SerializeUint32(0),
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
