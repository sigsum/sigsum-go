# sigsum-go

Sigsum is a system for public and transparent logging of signed
checksums, see [sigsum.org][] for an overview of the system.

This repository contains a Go library and client tools for interacting
with the system servers.

[sigsum.org]: https://www.sigsum.org/

## Documentation

The [doc](./doc) directory includes documentation of these tools, and
the file formats for the policy files and the proofs of logging used
by the tools. See <https://www.sigsum.org/docs/> for protocol
specifications, and documentation of other parts of the Sigsum system.

See the [RELEASES](./RELEASES.md) file for information about how
sigsum-go is released, and the [NEWS](./NEWS) file for a summary of
changes between releases.

## Development

You are encouraged to file [issues][] and open merge requests. Sign up
on our GitLab instance or login using a supported identity provider
like GitHub.

[issues]: https://git.glasklar.is/sigsum/core/sigsum-go/-/issues

### Testing

Besides go unit tests (`go test ./...`), the [tests](./tests)
directory contains integration tests for all command line tools, in
the form of shell scripts. They are all run by the top-level `make
check` Makefile target.

## Contact

  - IRC room `#sigsum` @ OFTC.net
  - Matrix room `#sigsum` which is bridged with IRC
  - The [sigsum-general][] mailing list

[sigsum-general]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-general.lists.sigsum.org/
