// package main provides a log and verification tool named sigsum
//
// Install:
//
//     $ go install git.sigsum.org/sigsum-go/cmd/sigsum@latest
//
// Usage:
//
//     $ sigsum help
//
package main

import (
	"flag"
	"fmt"
	stdlog "log"
	"os"

	"git.sigsum.org/sigsum-go/cmd/sigsum/hash"
	"git.sigsum.org/sigsum-go/cmd/sigsum/log"
	"git.sigsum.org/sigsum-go/cmd/sigsum/namespace"
	"git.sigsum.org/sigsum-go/cmd/sigsum/policy"
	"git.sigsum.org/sigsum-go/cmd/sigsum/verify"

	"git.sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum is a tool that logs and verifies signed checksums

Usage:

  sigsum COMMAND <options>
  sigsum COMMAND help

Commands:

  - policy     # output a new log and witness policy
  - hash       # output a new checksum
  - namespace  # output a new ssh namespace
  - log        # log ssh-signed checksums
  - verify     # verify a logged signed checksum

Quick start and cheat-sheet:

  # KEY GENERATION
  ssh-keygen -t ed25519
  # BASIC SETUP
  sudo mkdir -p /etc/sigsum
  sigsum policy default | sudo tee /etc/sigsum/policy
  echo "alice@example.org $(cat ~/.ssh/id_ed25519.pub)" | sudo tee --append /etc/sigsum/allowed_signers
  # SIGN A CHECKSUM
  sigsum hash -m "msg" | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n $(sigsum namespace) -O hashalg=sha256 > FILE.sig
  sigsum hash -f FILE  | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n $(sigsum namespace) -O hashalg=sha256 > FILE.sig
  # LOG SIGNED CHECKSUM
  sigsum log -d example.org FILE.sig # rate-limit via dns
  sigsum log -t XXXXXXXXXXX FILE.sig # rate-limit via token
  # VERIFY SIGNED CHECKSUM
  sigsum verify -m "msg" -I alice@example.org -s FILE.sig
  sigsum verify -f FILE  -I alice@example.org -s FILE.sig
`

func main() {
	var err error

	stdlog.SetFlags(0)
	opt := options.New(os.Args[1:], func() { stdlog.Printf(usage[1:]) }, func(_ *flag.FlagSet) {})
	switch opt.Name() {
	case "help", "":
		opt.Usage()
	case "policy":
		err = policy.Main(opt.Args())
	case "hash":
		err = hash.Main(opt.Args())
	case "namespace":
		err = namespace.Main(opt.Args())
	case "log":
		err = log.Main(opt.Args())
	case "verify":
		err = verify.Main(opt.Args())
	default:
		err = fmt.Errorf(": invalid command %q, try \"help\"", opt.Name())
	}

	if err != nil {
		format := "sigsum %s%s"
		if len(opt.Name()) == 0 {
			format = "sigsum%s%s"
		}

		stdlog.Printf(format, opt.Name(), err.Error())
		os.Exit(1)
	}
}
