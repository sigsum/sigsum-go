package ssh

import (
	"bytes"
	"encoding/hex"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestParsePrivateKeyFile(t *testing.T) {
	// Generated with ssh-keygen -q -N '' -t ed25519 -f test.key
	testPriv := []byte(
		`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCA7NJS5FcoZ5MTq9ad2sujyYF+KwjHjZRV6Q8maqHQeAAAAJjnOhbl5zoW
5QAAAAtzc2gtZWQyNTUxOQAAACCA7NJS5FcoZ5MTq9ad2sujyYF+KwjHjZRV6Q8maqHQeA
AAAEAwD0Vne2KfZCN+zKUSrRai+/6Vz5ivCQrvT1wU47e1SoDs0lLkVyhnkxOr1p3ay6PJ
gX4rCMeNlFXpDyZqodB4AAAADm5pc3NlQGJseWdsYW5zAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
`)
	testPub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIDs0lLkVyhnkxOr1p3ay6PJgX4rCMeNlFXpDyZqodB4"
	pub, signer, err := ParsePrivateKeyFile(testPriv)
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if got, want := signer.Private(),
		mustDecodeHex(t, "300f45677b629f64237ecca512ad16a2fbfe95cf98af090aef4f5c14e3b7b54a"); got != want {
		t.Errorf("unexpected private key: %x, expected %x", got, want)
	}
	if pub != signer.Public() {
		t.Errorf("inconsistent public key, doesn't match signer.Public()")
	}
	pubFromFile, _, err := ParsePublicEd25519(testPub)
	if err != nil {
		t.Fatalf("failed to parse pubkey file")
	}
	if pub != pubFromFile {
		t.Errorf("inconsistent public key, doesn't match pubkey file")
	}
}

func TestWritePrivateKeyFile(t *testing.T) {
	expFile := []byte(
		`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDGPZYiP3oZYapEsY1zR4NQFx99FB/NNkkAY+1dWkur1gAA
AIgwMTIzMDEyMwAAAAtzc2gtZWQyNTUxOQAAACDGPZYiP3oZYapEsY1zR4NQFx99
FB/NNkkAY+1dWkur1gAAAEDerb7vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AMY9liI/ehlhqkSxjXNHg1AXH30UH802SQBj7V1aS6vWAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`)
	nonce := [4]byte{'0', '1', '2', '3'}
	priv := crypto.PrivateKey{0xde, 0xad, 0xbe, 0xef}
	var buf bytes.Buffer

	if err := writePrivateKeyFile(&buf, crypto.NewEd25519Signer(&priv), nonce); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), expFile) {
		t.Errorf("unexpected file:\n%s", buf.Bytes())
	}
	_, signer, err := ParsePrivateKeyFile(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to parse private key file: %v", err)
	}
	if got := signer.Private(); got != priv {
		t.Errorf("unexpected privatekey %x, wanted %x", got, priv)
	}
}

func mustDecodeHex(t *testing.T, s string) (out crypto.PrivateKey) {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != len(out) {
		t.Fatalf("unexpected length of hex data, expected %d, got %d", len(out), len(b))
	}
	copy(out[:], b)
	return
}
