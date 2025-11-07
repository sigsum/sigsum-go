# Releases of sigsum-go

## What is a release?

A release of sigsum-go is a git tag that is mentioned in the [NEWS][]
file, and announced on the [sigsum-announce][] mailing list. (I.e.,
not all tags are considered releases).

[NEWS]: ./NEWS
[sigsum-announce]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-announce.lists.sigsum.org/

## What is being released?

### Command line programs

The following programs are released and supported:

- `./cmd/sigsum-key`
- `./cmd/sigsum-policy`
- `./cmd/sigsum-submit`
- `./cmd/sigsum-token`
- `./cmd/sigsum-verify`

User visible changes in these tools are documented in the [NEWS][]
file.

There are two additional programs, currently not properly supported:
`./cmd/sigsum-monitor` is work-in-progress. `./cmd/sigsum-witness` is
intended mainly for test purposes (to operate a witness, see
[litewitness][]).

[litewitness]: https://github.com/FiloSottile/litetlog/tree/main/cmd/litewitness

### Builtin named policies

A set of builtin named policies are included as files in the
`./pkg/policy/builtin/` directory. Those are embedded in the built
executable files. The contents of each builtin policy can be shown
using the `sigsum-policy` program.

### Library

The Go library (exported packages under `./pkg`) is intended for
applications that want to implement Sigsum logging, without going via
the command line tools. However, we are not yet able to promise API
stability (as indicated by the "v0.*" module version), and there's no
documentation beyond what's included in the source code.
