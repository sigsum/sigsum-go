package key

import (
	"fmt"

	"sigsum.org/key-mgmt/pkg/agent"
	"sigsum.org/key-mgmt/pkg/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
)

type AgentSigner struct {
	signer    agent.Signer
	publicKey crypto.PublicKey
}

func (s *AgentSigner) Sign(message []byte) (crypto.Signature, error) {
	signature, err := s.signer.Sign(message)
	if err != nil {
		return crypto.Signature{}, err
	}
	signature, err = ssh.ParseBytes(signature, ssh.ReadEd25519Signature)
	if err != nil {
		return crypto.Signature{}, err
	}
	var res crypto.Signature
	copy(res[:], signature)
	return res, nil
}

func (s *AgentSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func NewAgentSigner(publicKey *crypto.PublicKey) (*AgentSigner, error) {
	client, err := agent.Connect()
	if err != nil {
		return nil, err
	}
	sshPublicKey := string(ssh.SerializeEd25519PublicKey(publicKey[:]))
	identities, err := client.RequestIdentities(100)
	if err != nil {
		return nil, err
	}
	for _, id := range identities {
		if id.PublicKey == sshPublicKey {
			return &AgentSigner{signer: client.NewSigner(sshPublicKey, 0), publicKey: *publicKey}, nil
		}
	}
	return nil, fmt.Errorf("agent available, but requested key not available")

}
