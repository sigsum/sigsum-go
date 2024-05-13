package ssh

import (
	"bytes"
	"encoding/base64"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func FormatPublicEd25519(pub *crypto.PublicKey) string {
	return "ssh-ed25519 " +
o		base64.StdEncoding.EncodeToString(ssh.SerializeEd25519PublicKey(pub)) +
		" sigsum key\n"
}
