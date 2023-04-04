# Sigsum command line tools

Documentation of Sigsum the command line tools, including `sigsum-key`,
`sigsum-submit` and `sigsum-verify`.

TODO: Add a table of contents?

# General conventions

There are several commands, some of which have sub commands, e.g.,
`sigsum-key gen`. The aim is that each command should address one
role, e.g., `sigsum-submit` is the tool to use to submit new items to
be a Sigsum log, and collect proof of public logging, and
`sigsum-verify` is the tool to do offline verification of such a
proof.

## Configuration

Command line options follow GNU conventions, with long and short
options, e.g., `-k` or `--key`, and a `--help` option to display usage
information.

Operation of several tools is controlled by a Sigsum policy, defined
by a separate [policy file](./policy.md). The location of the policy
file is specified using the `--policy` option. 

There are no default locations for policy file or keys, and no other
configuration files read by default.

## Key handling

The ED25519 digital signature scheme is used for all Sigsum
signatures, hence all keys are ED25519 keys.

### Public keys

Public key files use OpenSSH format: A single line of the form 
```
ssh-ed25519 <base64> [optional comment]
```
where the base64 blob in turn represent [SSH wire
format](https://www.rfc-editor.org/rfc/rfc8709#name-public-key-format).
In certain places, in particular, in the policy file, public keys are used in "raw" form, without this wrapping.
Then an ED25519 public key is 32 octets in the format defined by [RFC
8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.2).

The `sigsum-key` tool can be used to convert between these two forms.

### Private keys

Private keys are stored as unencrypted OpenSSH private key files
(i.e., PEM-like files with a tag OPENSSH PRIVATE KEY, and contents
defined by [OpenSSH key
format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key).

Using unencrypted private keys on disk may be adequate fro some use
cases, e.g., for the key used for signing the submit tokens used for
domain-based rate limiting.

To support other kinds of key storage, the key can be made available
via the [ssh-agent
protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent).
Whenever the tools need a signing key, they accept the name of either
an unencrypted private key file as above, or the name of a public key
file. In the latter case, the tools access the corresponding private
key by connecting to the ssh-agent listening on `${SSH_AUTH_SOCK}`.

For private keys of high value, it is recommended that keys are stored
in a hardware token providing a signing oracle, and made accessible
to appropriate users via the ssh-agent protocol.

# The `sigsum-key` tool

# The `sigsum-submit` tool

# The `sigsum-verify` tool

# The `sigsum-token` tool
