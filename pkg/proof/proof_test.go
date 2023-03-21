package proof

import (
	"bytes"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
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
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=7e28 518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 5c46852140e41b49925f8c93dee5c3e776ababdd230425d17f44b519f5565e0026f86aea998ccb7685fbc672c7d016a3940db5d684279a39c870318c840bf002

size=4
root_hash=ca5e9898dd77d24019bee526e3cafa2c0c2c47e82897f5d237fdfa6f132ec0a8
signature=207347dc94e5ca8525a2d03901223064c96fa7a245f502c64b6dff2d50d6dd3bc9e809f81e0867b839e41e73296876dcef514ec5f323ccadd3cc5b0b0049730f

leaf_index=3
node_hash=8a419a476109a749732ee0d9845470c995ae6502225647f4b3bbb1dff61a5b4f
node_hash=eb94766b094058835d61c551a8ef581e8242ea419b665a2d2043291b98524e14
`
	msg := crypto.Hash{
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'f', 'o', 'o', '-', '4', '\n',
	}
	logKey, err := key.ParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOT0CqHzICIK3DRDmXzoru/YdK/hYyPIzWfRxDobFene")
	if err != nil {
		t.Fatal(err)
	}
	submitKey, err := key.ParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIESXzsjTWflm2LJne0G74+1cURkMn2WDsKt0RfwxTdsL")
	if err != nil {
		t.Fatal(err)
	}
	var proof SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(proofASCII)); err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyNoCosignatures(&msg, &submitKey, &logKey); err != nil {
		t.Fatal(err)
	}
	// TODO: Test invalidatign proof in different ways.
}
