package dns

import (
	"context"
	"log"
	"testing"
	"time"

	"git.sigsum.org/sigsum-lib-go/pkg/hex"
	"git.sigsum.org/sigsum-lib-go/pkg/types"
)

func Example() {
	name := "_sigsum_v0.testonly.sigsum.org"
	pub := mustDecodePublicKey("cda2517e17dcba133eb0e71bf77473f94a77d7e61b1de4e1e64adfd0938d6182")

	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dr := NewDefaultResolver()
	if err := dr.Verify(ctx, name, pub); err != nil {
		log.Fatal(err.Error())
	}

	// Output:
}

func TestValidResponse(t *testing.T) {
	pub := mustDecodePublicKey("cda2517e17dcba133eb0e71bf77473f94a77d7e61b1de4e1e64adfd0938d6182")
	for _, table := range []struct {
		desc   string
		rsps   []string
		wantOK bool
	}{
		{
			desc: "invalid: upper-case hex-encoding",
			rsps: []string{
				"",
				"abc",
				"C522D929B261241EEF174B51B8472FA5D5F961892089A7B85FD25CE73271ABCA",
				"defghi",
			},
		},
		{
			desc: "valid",
			rsps: []string{
				"",
				"abc",
				"c522d929b261241eef174b51b8472fa5d5f961892089a7b85fd25ce73271abca",
				"defghi",
			},
			wantOK: true,
		},
	} {
		err := validResponse(pub, table.rsps)
		if got, want := err == nil, table.wantOK; got != want {
			t.Errorf("got error but wanted none in test %q: %v", table.desc, err)
		}
	}
}

func TestValidPrefix(t *testing.T) {
	for _, table := range []struct {
		desc   string
		name   string
		wantOK bool
	}{
		{
			desc: "invalid: bad prefix (1/2)",
			name: "x_sigsum_v0.sigsum.org",
		},
		{
			desc: "invalid: bad prefix (2/2)",
			name: "_sigsum_v0x.sigsum.org",
		},
		{
			desc:   "valid",
			name:   "_sigsum_v0.sigsum.org",
			wantOK: true,
		},
	} {
		err := validPrefix(table.name)
		if got, want := err == nil, table.wantOK; got != want {
			t.Errorf("got error but wanted none in test %q: %v", table.desc, err)
		}
	}
}

func mustDecodePublicKey(str string) *types.PublicKey {
	b, err := hex.Deserialize(str)
	if err != nil {
		log.Fatal(err.Error())
	}
	if len(b) != types.PublicKeySize {
		log.Fatal("invalid key size")
	}

	var pub types.PublicKey
	copy(pub[:], b)
	return &pub
}
