package types

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

const (
	CheckpointNamePrefix = "sigsum.org/v1/tree/"
	CosignatureNamespace = "cosignature/v1"
)

type noteSignatureType byte

const (
	signatureTypeEd25519     noteSignatureType = 0x01
	signatureTypeCosignature noteSignatureType = 0x04
)

type noteKeyId [4]byte

func checkpointSigsumOriginFromHash(keyHash *crypto.Hash) string {
	return fmt.Sprintf("%s%x", CheckpointNamePrefix, *keyHash)
}

func checkpointSigsumOrigin(publicKey *crypto.PublicKey) string {
	keyHash := crypto.HashBytes(publicKey[:])
	return checkpointSigsumOriginFromHash(&keyHash)
}

func checkpointCosignedData(timestamp uint64, body string) string {
	return fmt.Sprintf("%s\ntime %d\n%s",
		CosignatureNamespace, timestamp, body)
}

func makeKeyId(keyName string, sigType noteSignatureType, pubKey *crypto.PublicKey) (res noteKeyId) {
	hash := crypto.HashBytes(bytes.Join([][]byte{[]byte(keyName), []byte{byte(sigType)}, pubKey[:]}, nil))
	copy(res[:], hash[:4])
	return
}

// Information needed to represent a (Sigsum9 log when creating or
// verifying checkpoints.
type CheckpointLog struct {
	PublicKey crypto.PublicKey
	KeyHash   crypto.Hash // TODO: Really needed?
	Origin    string
	KeyId     noteKeyId
}

func NewCheckpointLog(publicKey *crypto.PublicKey) CheckpointLog {
	keyHash := crypto.HashBytes(publicKey[:])
	origin := checkpointSigsumOriginFromHash(&keyHash)
	return CheckpointLog{
		PublicKey: *publicKey,
		KeyHash:   keyHash,
		Origin:    origin,
		KeyId:     makeKeyId(origin, signatureTypeEd25519, publicKey),
	}
}

func writeNoteSignature(w io.Writer, keyName string, sig []byte) error {
	_, err := fmt.Fprintf(w, "\u2014 %s %s\n", keyName, base64.StdEncoding.EncodeToString(sig))
	return err
}

func (log *CheckpointLog) WriteLogSignature(w io.Writer, sig *crypto.Signature) error {
	return writeNoteSignature(w, log.Origin, bytes.Join([][]byte{log.KeyId[:], sig[:]}, nil))
}

// See https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md for
// specification.
func (log *CheckpointLog) WriteCheckpoint(w io.Writer, sth *SignedTreeHead) error {
	if _, err := fmt.Fprintf(w, "%s\n", sth.formatCheckpoint(log.Origin)); err != nil {
		return err
	}

	return log.WriteLogSignature(w, &sth.Signature)

}

func WriteNoteCosignature(w io.Writer, keyName string, keyId noteKeyId, timestamp uint64, sig *crypto.Signature) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], timestamp)
	return writeNoteSignature(w, keyName, bytes.Join([][]byte{keyId[:], buf[:], sig[:]}, nil))
}

// Represent a half-processed signature line.
type signatureLine struct {
	keyName   string
	keyId     noteKeyId
	signature crypto.Signature
}

// Input is a single signature line, with no trailing newline character.
// Fails if signature blob is not of the expected size.
func parseSignatureLine(line string, prefixSize int) (signatureLine, []byte, error) {
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "\u2014" {
		return signatureLine{}, nil, fmt.Errorf("invalid signature line %q", line)
	}
	signature, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return signatureLine{}, nil, fmt.Errorf("invalid base signature on line %q: %v", line, err)
	}
	if want := 4 + prefixSize + crypto.SignatureSize; len(signature) != want {
		return signatureLine{}, nil, fmt.Errorf("unexpected signature blob size, got %d, wanted %d, on line %q", len(signature), want, line)
	}
	res := signatureLine{keyName: fields[1]}
	copy(res.keyId[:], signature[:4])
	copy(res.signature[:], signature[4+prefixSize:])

	return res, signature[4 : 4+prefixSize], nil
}

// Parse note, keeping only signatures of Ed25519 size.
func parseNote(note string) (string, []signatureLine, error) {
	sep := strings.LastIndex(note, "\n\n")
	if sep < 0 {
		return "", nil, fmt.Errorf("malformed signed note, no empty line found")
	}
	body := note[:sep+1] // Include the first of the two newline characters.
	lines := strings.Split(note[sep+2:], "\n")

	signatures := make([]signatureLine, 0, len(lines))
	for i, line := range lines {
		// Our normal case is that the note ends with a
		// newline, resulting in an empty element at the end
		// of the lines array.
		if i == len(lines)-1 && line == "" {
			break
		}
		signature, _, err := parseSignatureLine(line, 0)
		// Silently ignore any errors.
		if err == nil {
			signatures = append(signatures, signature)
		}
	}
	return body, signatures, nil
}

// Rejects checkpoints with additional lines.
func parseCheckpointBody(body, origin string) (TreeHead, error) {
	lines := strings.Split(body, "\n") // Terminating newline makes Split return an empty string at the end.
	if len(lines) != 4 || lines[3] != "" {
		return TreeHead{}, fmt.Errorf("invalid checkpoint, expected 3 lines body, got %d lines", len(lines)-1)
	}
	if lines[0] != origin {
		return TreeHead{}, fmt.Errorf("unexpected checkpoint origin, got %q, expected %q", lines[0], origin)
	}
	size, err := ascii.IntFromDecimal(lines[1])
	if err != nil {
		return TreeHead{}, fmt.Errorf("invalid checkpoint, bad size %q", lines[1])
	}
	rootHash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return TreeHead{}, fmt.Errorf("invalid checkpoint, bad root hash %q: %v", lines[2], err)
	}
	if len(rootHash) != 32 {
		return TreeHead{}, fmt.Errorf("invalid checkpoint, root hash %q has wrong size", lines[2])
	}
	th := TreeHead{Size: size}
	copy(th.RootHash[:], rootHash)
	if size == 0 && th.RootHash != merkle.HashEmptyTree() {
		return TreeHead{}, fmt.Errorf("unexpected root hash %x for empty tree", th.RootHash)
	}
	return th, nil
}

// Checks only the log's signature, ignores any other signature lines,
// including cosignatures.
func (log *CheckpointLog) ParseCheckpoint(checkpoint string) (SignedTreeHead, error) {
	body, signatures, err := parseNote(checkpoint)
	if err != nil {
		return SignedTreeHead{}, err
	}
	for _, line := range signatures {
		if line.keyName != log.Origin || line.keyId != log.KeyId {
			continue
		}
		if crypto.Verify(&log.PublicKey, []byte(body), &line.signature) {
			th, err := parseCheckpointBody(body, log.Origin)
			if err != nil {
				return SignedTreeHead{}, err
			}
			return SignedTreeHead{TreeHead: th, Signature: line.signature}, nil
		}
	}
	return SignedTreeHead{}, fmt.Errorf("checkpoint has no valid log signature")
}

// Expects signature with a particular witness public key, and ignores
// the key name on the line, except that it is used to match the
// keyId.
func ParseCheckpointCosignature(body string, in string, publicKey *crypto.PublicKey) (Cosignature, error) {
	line, prefix, err := parseSignatureLine(in, 8)
	if err != nil {
		return Cosignature{}, err
	}
	if keyId := makeKeyId(line.keyName, signatureTypeCosignature, publicKey); line.keyId != keyId {
		return Cosignature{}, fmt.Errorf("unexpected signature keyId")
	}

	timestamp := binary.BigEndian.Uint64(prefix)

	msg := checkpointCosignedData(timestamp, body)
	if !crypto.Verify(publicKey, []byte(msg), &line.signature) {
		return Cosignature{}, fmt.Errorf("invalid cosignature")
	}
	return Cosignature{
		KeyHash:   crypto.HashBytes(publicKey[:]),
		Timestamp: timestamp,
		Signature: line.signature,
	}, nil
}
