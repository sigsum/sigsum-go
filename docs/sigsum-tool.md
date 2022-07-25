# The sigsum tool

The sigsum tool is used to log and verify SSH-signed checksums.  This document
gives you a hands-on introduction to help you get started with sigsum logging
without having to read any lengthy background.

## Prerequisites

You will need:

  - [Go][], at least version 1.15. 
    Check version with `go version`.
  - `ssh-keygen`, at least [OpenSSH release 8.9][].
     Check version with `sshd -v`.

[OpenSSH release 8.9]: https://www.openssh.com/txt/release-8.9
[Go]: https://go.dev/doc/install

You may want somewhere to place the data associated with your signed checksums.
Examples include a public git repository or a web server.  This is optional.  We
will use [git.sigsum.org/testing/tree/data][] for demo purposes.

[git.sigsum.org/testing/tree/data]: https://git.sigsum.org/testing/tree/data.

## Install

    $ go install git.sigsum.org/sigsum-go/cmd/sigsum@latest
    $ sigsum help
    ...

## Getting started

docdoc

## Further reading

  - Introductory blog post on [SSH signing][] by Andrew Ayer
  - Sigsum logging [design document][] and [api specification][]
  - How sigsum logs can be operated in a [primary-secondary mode][]

[SSH signing]: https://www.agwa.name/blog/post/ssh_signatures
[design document]: https://git.sigsum.org/sigsum/tree/doc/design.md
[api specification]: https://git.sigsum.org/sigsum/tree/doc/api.md
[primary-secondary mode]: https://git.sigsum.org/log-go/tree/doc/design.md
