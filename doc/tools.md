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
In certain places, in particular, in the policy file, public keys are
used in "raw" form, without this wrapping. Then an ED25519 public key
is 32 octets in the format defined by [RFC
8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.2).

The `sigsum-key` tool can be used to convert between these two forms.

### Private keys

Private keys are stored as unencrypted OpenSSH private key files
(i.e., PEM files with a tag OPENSSH PRIVATE KEY, and contents
defined by [OpenSSH key
format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)).

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

The `sigsum-key` can generate new keys, create and verify signatures,
and convert between different key formats.

## Key generation

To generate a new key pair, run
```
sigsum-key gen -o KEY-FILE
```
This generates a new ED25519 keypair (with key material provided by
the crypto/rand module in the golang standard library). The private
key is stored to the given output KEY-FILE, in OpenSSH format. The
private key is *not* encrypted, but stored with restrictive file
permissions. The corresponding public key is written to a file with an
added ".pub" suffix, in OpenSSH format.

Behavoir is similar to the OpenSSH key generation utility, if invoked
like
```
ssh-keygen -q -N '' -t ed25519 -f KEY-FILE
```

## Public key conversion

As explained above, OpenSSH format is the main representation for
public Sigsum keys, when stored in key files. Such a public key can be
converted to a raw form using
```
sigsum-key hex -k KEY-FILE
```
The hex representation is used in the Sigsum policy file, and in
messages on the wire. For the opposite conversion, use

```
sigsum-key hex-to-pub -k HEX-FILE
```

Occasionally, also the key hash is needed; it is used in certain
messages on the wire, and in the Sigsum log server's [rate
limit](https://git.glasklar.is/sigsum/core/log-go/-/blob/main/doc/rate-limit.md)
configuration. The key hash can be computed using
```
sigsum-key hash -k KEY-FILE
```

These three conversion tools read stdin and write stdout by default,
it's optional to specify an input file, with `-k`, or output file,
with `-o`.

## Sign and verify operations

The sigsum-key tool can also create and verify signatures using
[OpenSSH signature
format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig).

Signing a message is done using
```
sigsum-key sign -k KEY-FILE [-n NAMESPACE] [-o FILE] [--ssh] < MSG
```

The `-k` option is required, and specifies the key to use for signing
(either an unencrypted private key, or a public key, if corresponding
private key is acessible via ssh-agent). The message to sign is read
from stdin. The default namespace (a feature of OpenSSH format
signatures) is the one used for a signatures in a Sigsum leaf. The
create dsignature is written to stdout, if no output file is specified
with the `-o` option.

By default, the signature is a raw hex representation of a 64-octet
ED25519 signature. With the `--ssh` option, the signatures is wrapped
in an OpenSSH signature file, a PEM file with the tag "SSH SIGNATURE".

Signatures can be verified using
```
sigsum-key verify -k KEY-FILE -s SIGNATURE-FILE [-n NAMESPACE] < MSG
```
The `-k `and `-s` options, specifying the public key and the
signature, are required. The namespace must match the namespace used
when the signature was created. The message signed is read from stdin.

The use of OpenSSH signature formats in the Sigsum protocols is under
discussion. If usage is dropped in version 1 of the Sigsum protocols,
these sub commands are likely to change.

# The `sigsum-submit` tool

# The `sigsum-verify` tool

# The `sigsum-token` tool
