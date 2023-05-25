package proof

import (
	"bytes"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
)

func TestASCII(t *testing.T) {
	for _, table := range []struct {
		desc  string
		ascii string
	}{
		// Examples from running sigsum-submit-test.
		{"size 1", `version=0
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=5cc0 518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 90c47772e2758fac56740ad52913af66874dc49b31ef21e4fab544a2836b7d9991f07559792f22c617c172e10391317b4a0a4396c4eb9cfc1871ed07a360240f

size=1
root_hash=b02bd71073448d7a3ee402892f96c9d78b712242deed7e6fd8a98abcde33f46d
signature=2eb4bfb59aa08531f325b8b233859d5c62187a311c7bb32e4cbd61e3a2b458d4e4451cfeb8a920d3cb4f755ed2f5f895628c0d92463f6f2d7d12fdf56f070d04
`},
		{"size 4", `version=0
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=7e28 518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 5c46852140e41b49925f8c93dee5c3e776ababdd230425d17f44b519f5565e0026f86aea998ccb7685fbc672c7d016a3940db5d684279a39c870318c840bf002

size=4
root_hash=ca5e9898dd77d24019bee526e3cafa2c0c2c47e82897f5d237fdfa6f132ec0a8
signature=207347dc94e5ca8525a2d03901223064c96fa7a245f502c64b6dff2d50d6dd3bc9e809f81e0867b839e41e73296876dcef514ec5f323ccadd3cc5b0b0049730f

leaf_index=3
node_hash=8a419a476109a749732ee0d9845470c995ae6502225647f4b3bbb1dff61a5b4f
node_hash=eb94766b094058835d61c551a8ef581e8242ea419b665a2d2043291b98524e14
`},
	} {
		indent := func(s string) string {
			return "  " + strings.ReplaceAll(s, "\n", "\n  ")
		}
		var proof SigsumProof
		if err := proof.FromASCII(bytes.NewBufferString(table.ascii)); err != nil {
			t.Errorf("%s: FromASCII failed, %v", table.desc, err)
			continue
		}
		var buf bytes.Buffer
		if err := proof.ToASCII(&buf); err != nil {
			t.Errorf("%s: ToASCII failed %v", table.desc, err)
			continue
		}
		if got, want := buf.String(), table.ascii; got != want {
			t.Errorf("%s: ascii roundtrip failed, got:\n%s\nexpected:\n%s",
				table.desc, indent(got), indent(want))
		}
	}
}

func TestVerifyNoCosignatures(t *testing.T) {
	// Example from running sigsum-submit-test.
	proofASCII := `version=0
log=1f8d4547082a5985ad0e59ffe219f7a065e09c6b77a0012daf276e5dd1805b4b
leaf=7e28 69512577a0f3c2695011ddc549756099017b7e2c8390341cbb24c57e886775f1 262737d935123272b9e3265fe2e38a014a9c1b13951e864737666251ada26dabbc6e699a4e527ec52a0be970e158abef35f087766d18d560853a44855119cf01

size=4
root_hash=7bca01e88737999fde5c1d6ecac27ae3cb49e14f21bcd3e7245c276877b899c9
signature=c60e5151b9d0f0efaf57022c0ec306c0f0275afef69333cc89df4fda328c87949fcfa44564f35020938a4cd6c1c50bc0349b2f54b82f5f6104b9cd52be2cd90e

leaf_index=3
node_hash=e7d222a285ca81fdc76bfcd5513408c87dd42a18e03d6c3b672a05982163c01b
node_hash=15cdc42440689a6f7599e09f61a4d638420cb58662f5994def1624ea4d923879
`
	msg := crypto.Hash{
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'f', 'o', 'o', '-', '4', '\n',
	}
	logKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6kw3w2BWjlKLdrtnv4IaN+zg8/RpKGA98AbbTwjpdQ")
	submitKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCMTGNMNe1HP2us/dR5dBpyrSPDgPQ9mX5j9iqbLIS+")
	var proof SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(proofASCII)); err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyNoCosignatures(&msg, &submitKey, &logKey); err != nil {
		t.Error(err)
	}
	// TODO: Test invalidating proof in different ways.
}

func TestVerify(t *testing.T) {
	// Example from running sigsum-submit-witness-test.
	proofASCII := `version=0
log=7c5fafc796c201e0fcd7567c5033a2777ec28363f54ea0ba97b57bece0d96acd
leaf=7e28 8a578b9649ba01b7d29dd557906975d68a3aec50e3f9c08690420b8c6426856d 79b489a38548a67d78f06221b014d41be58b703237d17b4f203f0dd4ead9e2597149c2f118894581ce7473a61fa880716af6ff2138bade2cecc4b297099bf104

size=4
root_hash=3ddc56fd46e71e517b6936b977a457da7d398108141fcdf5c8386cdd724ab7a8
signature=ccbdd8c784726b732b8edd2039fbad5506e4acccd56e3e5d86c0ee109b3d2662e6881fe3d09fc48f9ddd31494463c5ec44926ff9158785ad1dd9b5d6434b0804
cosignature=v1 bd8385aa82e07c3e1e297a1600c12bb25ce7a9490b5c1287ec30e09ac4c8b884 1683202758 e8d6c447d7847d5c1431ef86f8c60fa0cbacd975388b2a8f202fe4b0f9d0d544989c9d9351752d86aae2df72b9d7135b6b09de2ccaa6d68edf638105d69be609

leaf_index=3
node_hash=61010ae798308f5b97237615ab8c1b14f2c782c37616e97d0a170b617bc7a4ce
node_hash=a5c3752be610d605ce5c64ee2e28ee5b94a1cc0a68742f18f24c9b5c82d07298
`
	msg := crypto.Hash{
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'f', 'o', 'o', '-', '4', '\n',
	}
	logKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl")
	submitKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II")
	witnessKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMvjV+a0ZASecDt75siSARk6zCoYwJWwaRqvULmx4VeK")

	var proof SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(proofASCII)); err != nil {
		t.Fatal(err)
	}
	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{logKey}, []crypto.PublicKey{witnessKey}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Verify(&msg, &submitKey, policy); err != nil {
		t.Error(err)
	}
	// TODO: Test invalidating proof in different ways.
}

func mustParsePublicKey(t *testing.T, ascii string) crypto.PublicKey {
	key, err := key.ParsePublicKey(ascii)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
