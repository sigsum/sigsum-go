package spam

import (
	"flag"
	"fmt"
	"log"
	"time"

	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/spam/leaf"
	"git.sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug spam sends many requests to a sigsum log

Usage:

  sigsum-debug spam leaf -u URL -k KEY -h DOMAIN_HINT [-d DURATION]
      [-i INTERVAL] [-w WAIT] [-s SUBMITTERS] [-c CHECKERS]

    Sends add-leaf requests to a sigsum log from one or more parallel
    submitters.  Use the -c option to also check for 200 OK responses.
    Unless the -w flag is specified, you then need ~5x more checkers.

    Options:
    -u, --log-url      URL of a log to spam with add-leaf requests
    -k, --private-key  Private key to sign checksums with in hex
    -h, --domain-hint  Domain hint for the specified private key
    -d, --duration     Duration to run sigsum-spam (Default: 5m)
    -i, --interval     Duration between emitting stats (Default: 1s)
    -w, --wait         Time to wait between submits (Default: 0s)
    -s, --submitters   Number of submitters to use (Default: 1)
    -c, --checkers     Number of checkers to use (Default: 0)
`

var (
	leafConfig leaf.Config
)

func setOptions(fs *flag.FlagSet) {
	switch cmd := fs.Name(); cmd {
	case "leaf":
		options.AddString(fs, &leafConfig.LogURL, "u", "log-url", "")
		options.AddString(fs, &leafConfig.PrivateKey, "k", "private-key", "")
		options.AddString(fs, &leafConfig.DomainHint, "h", "domain-hint", "")
		options.AddDuration(fs, &leafConfig.Duration, "d", "duration", 5*time.Minute)
		options.AddDuration(fs, &leafConfig.Interval, "i", "interval", 1*time.Second)
		options.AddDuration(fs, &leafConfig.Wait, "w", "wait", 0*time.Second)
		options.AddUint64(fs, &leafConfig.NumSubmitters, "s", "submitters", 1)
		options.AddUint64(fs, &leafConfig.NumCheckers, "c", "checkers", 0)
	}
}

func Main(args []string) error {
	var err error

	opt := options.New(args, func() { log.Printf(usage[1:]) }, setOptions)
	if err == nil {
		switch opt.Name() {
		case "help", "":
			opt.Usage()
		case "leaf":
			err = leaf.Main(opt.Args(), leafConfig)
		default:
			err = fmt.Errorf("invalid command %q, try \"help\"", opt.Name())
		}
	}
	if err != nil {
		format := " %s: %w"
		if len(opt.Name()) == 0 {
			format = "%s: %w"
		}
		err = fmt.Errorf(format, opt.Name(), err)
	}

	return err
}
