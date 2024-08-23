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

func sigsumLogOrigin(keyHash *crypto.Hash) string {
	return fmt.Sprintf("%s%x", CheckpointNamePrefix, keyHash)
}

func checkpointCosignedData(timestamp uint64, body string) string {
	return fmt.Sprintf("%s\ntime %d\n%s",
		CosignatureNamespace, timestamp, body)
}

func makeKeyId(keyName string, sigType noteSignatureType, pubKey *crypto.PublicKey) (res [4]byte) {
	hash := crypto.HashBytes(bytes.Join([][]byte{[]byte(keyName), []byte{byte(sigType)}, pubKey[:]}, nil))
	copy(res[:], hash[:4])
	return
}

func CheckpointLogKeyId(pubKey *crypto.PublicKey) [4]byte {
	keyHash := crypto.HashBytes(pubKey[:])
	return makeKeyId(sigsumLogOrigin(&keyHash), signatureTypeEd25519, pubKey)
}

func writeNoteSignature(w io.Writer, origin string, sig []byte) error {
	_, err := fmt.Fprintf(w, "\u2014 %s %s\n", origin, base64.StdEncoding.EncodeToString(sig))
	return err
}

func WriteNoteLogSignature(w io.Writer, origin string, keyId [4]byte, sig *crypto.Signature) error {
	return writeNoteSignature(w, origin, bytes.Join([][]byte{keyId[:], sig[:]}, nil))
}

func WriteNoteCosignature(w io.Writer, origin string, keyId [4]byte, timestamp uint64, sig *crypto.Signature) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], timestamp)
	return writeNoteSignature(w, origin, bytes.Join([][]byte{keyId[:], buf[:], sig[:]}, nil))
}

// Represent a half-processed signature line.
type signatureLine struct {
	keyName string
	keyId   [4]byte
	// Always at least the size of an ed25519 signature, i.e., 32 bytes.
	signature []byte
}

// Imput is a single signature line, with new trailign newline character.
func parseSignatureLine(line string) (signatureLine, error) {
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "\u2014" {
		return signatureLine{}, fmt.Errorf("invalid signature line %q", line)
	}
	signature, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return signatureLine{}, fmt.Errorf("invalid base signature on line %q: %v", line, err)
	}
	if len(signature) < 36 {
		return signatureLine{}, fmt.Errorf("signature blob too short on line %q: %v", line, err)
	}
	var keyId [4]byte
	copy(keyId[:], signature[:4])
	return signatureLine{keyName: fields[1], keyId: keyId, signature: signature[4:]}, nil

}

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
		signature, err := parseSignatureLine(line)
		if err != nil {
			return "", nil, fmt.Errorf("error in signature line #%d: %v", i, err)
		}
		signatures = append(signatures, signature)
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

// Checks only the logs signature, ignores any other signature lines,
// including cosignatures.
func ParseCheckpoint(checkpoint string, logKey *crypto.PublicKey) (SignedTreeHead, error) {
	keyHash := crypto.HashBytes(logKey[:])
	origin := sigsumLogOrigin(&keyHash)
	keyId := makeKeyId(origin, signatureTypeEd25519, logKey)

	body, signatures, err := parseNote(checkpoint)
	if err != nil {
		return SignedTreeHead{}, err
	}
	for _, signature := range signatures {
		var sig crypto.Signature
		if signature.keyName != origin || signature.keyId != keyId {
			continue
		}
		if len(signature.signature) != len(sig) {
			continue
		}
		copy(sig[:], signature.signature)
		if crypto.Verify(logKey, []byte(body), &sig) {
			th, err := parseCheckpointBody(body, origin)
			if err != nil {
				return SignedTreeHead{}, err
			}
			return SignedTreeHead{TreeHead: th, Signature: sig}, nil
		}
	}
	return SignedTreeHead{}, fmt.Errorf("checkpoint has no valid log signature")
}

// Expects signature with a particular witness public key, and ignores
// the key name on the line, except that it is used to match the
// keyId.
func ParseCheckpointCosignature(body string, line string, pubKey *crypto.PublicKey) (Cosignature, error) {
	signature, err := parseSignatureLine(line)
	if err != nil {
		return Cosignature{}, err
	}
	if len(signature.signature) != 40 {
		return Cosignature{}, fmt.Errorf("unexpected signature size")
	}
	if keyId := makeKeyId(signature.keyName, signatureTypeCosignature, pubKey); signature.keyId != keyId {
		return Cosignature{}, fmt.Errorf("unexpected signature keyId")
	}

	timestamp := binary.BigEndian.Uint64(signature.signature[:8])

	msg := checkpointCosignedData(timestamp, body)
	var sig crypto.Signature
	copy(sig[:], signature.signature[8:])
	if !crypto.Verify(pubKey, []byte(msg), &sig) {
		return Cosignature{}, fmt.Errorf("invalid cosignature")
	}
	return Cosignature{
		KeyHash:   crypto.HashBytes(pubKey[:]),
		Timestamp: timestamp,
		Signature: sig,
	}, nil
}
