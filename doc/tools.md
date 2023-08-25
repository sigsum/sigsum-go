# Sigsum command line tools

Documentation of the Sigsum command line tools, including `sigsum-key`,
`sigsum-submit` and `sigsum-verify`.

## Table of contents
  * [General conventions tool](#general-conventions)
  * [The sigsum-key tool](#the-sigsum-key-tool)
  * [The sigsum-submit tool](#the-sigsum-submit-tool)
  * [The sigsum-verify tool](#the-sigsum-verify-tool)
  * [The sigsum-token tool](#the-sigsum-token-tool)

# General conventions

There are several tools, some of which have sub commands, e.g.,
`sigsum-key gen`. The aim is that each command should address one
task, e.g., `sigsum-submit` is the tool to use to submit new items to
a Sigsum log, and collect proof of public logging, and
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

The Ed25519 digital signature scheme is used for all Sigsum
signatures, hence all keys are Ed25519 keys.

### Public keys

Public key files use OpenSSH format: A single line of the form 
```
ssh-ed25519 <base64> [optional comment]
```
where the base64 blob in turn represent [SSH wire
format](https://www.rfc-editor.org/rfc/rfc8709#name-public-key-format).
In certain places, in particular, in the policy file, public keys are
used in "raw" form, without this wrapping. Then an Ed25519 public key
is 32 octets in the format defined by [RFC
8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.2).

The `sigsum-key` tool can be used to convert between these two forms.

### Private keys

Private keys are stored as unencrypted OpenSSH private key files
(i.e., PEM files with a tag OPENSSH PRIVATE KEY, and contents
defined by [OpenSSH key
format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)).

Using unencrypted private keys on disk may be adequate for some use
cases, e.g., for the key used to sign the submit tokens used for
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

The `sigsum-key` tool can generate new keys, create and verify signatures,
and convert between different key formats.

## Key generation

To generate a new key pair, run
```
sigsum-key gen -o KEY-FILE
```
This generates a new Ed25519 keypair (with key material provided by
the `crypto/rand` module in the golang standard library). The private
key is stored to the given output KEY-FILE, in OpenSSH format. The
private key is *not* encrypted, but stored with restrictive file
permissions. The corresponding public key is written to a file with an
added ".pub" suffix, in OpenSSH format.

Behavior is similar to the OpenSSH key generation utility, if invoked
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

These three conversion tools read standard input and write to standard
output by default. It's optional to specify an input file, with `-k`,
or output file, with `-o`.

## Sign and verify operations

The `sigsum-key` tool can also create and verify signatures.

Signing a message is done using
```
sigsum-key sign -k KEY-FILE [-n NAMESPACE] [-o FILE] < MSG
```

The `-k` option is required, and specifies the key to use for signing
(either an unencrypted private key, or a public key, if corresponding
private key is accessible via ssh-agent). The message to sign is read
from standard input. If a non-empty namespace is provided, the
namespace string and a NUL character is prepended to the message
before it is signed with Ed25519. The created signature, in hex
representation, is written to standard output, if no output file is
specified with the `-o` option.

Signatures can be verified using
```
sigsum-key verify -k KEY-FILE -s SIGNATURE-FILE [-n NAMESPACE] < MSG
```
The `-k `and `-s` options, specifying the public key and the
signature, are required. The namespace must match the namespace used
when the signature was created. The message signed is read from
standard input.

## Examples

Create a new private key file "example.key" and corresponding public
key file "example.key.pub".
```
$ sigsum-key gen -o example.key
```

Sign a message using that key.
```
$ echo Hello | sigsum-key sign  -k example.key -o hello.sign
```

Verify the signature, with exit code indicating success or failure. On
success, there is no output.
```
$ echo Hello | sigsum-key verify -s hello.sign -k example.key.pub
$ echo Helloo | sigsum-key verify -s hello.sign -k example.key.pub
signature is not valid
```

Convert key to raw hex format.
```
$ sigsum-key hex -k example.key.pub
e0863b18794d2150f3999590e0e508c09068b9883f05ea65f58cfc0827130e92
```

# The `sigsum-submit` tool

The `sigsum-submit` tool is used to create and/or submit add-leaf
requests to a Sigsum log (as defined in the [Sigsum
spec](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md).

To create and immediately submit one or more requests, pass both of
the `-k` (signing key) and `-p` (policy) options, described below.

To separate these two parts of the process (e.g., if the machine with
access to the private signing key does not have Internet connectivity),
first run `sigsum-submit -k` to create and sign the request. Collect
the output, which in this case is the body of a Sigsum add-leaf
request, and pass that as input input to `sigsum -p` later on, to
submit it to a log.

## Inputs

Each input to `sigsum-submit` is either a message, a message hash, or
a leaf request, depending on other options. Input files are provided
on the command line; if no arguments are provided, a single input is
read from standard input.

## Outputs

If the input is read from standard input, by default, the output of
`sigsum-submit`, if any, is written to standard output. The `-o`
option can be used to redirect output to the specified file (any
existing file is overwritten).

For file inputs, there's one output file for each input file. The name
of the output file is constructed as follows:

1. If there's exactly one input file, and the -o option is used,
   output is written to that file. Any existing file is overwritten.

2. For a request output, the suffix ".req" is added to the input
   file name.

3. For a proof output, if the input is a request, any ".req"
   suffix on the input file name is stripped. Then the suffix
   ".proof" is added.

4. If the --output-dir option is provided, any directory part of
   the input file name is stripped, and the output is written as a
   file in the specified output directory.

When output is written to a named file (i.e., not to standard output),
the output is first written to a temporary file, which is atomically
renamed to the specified name only on success.

The tool can log various diagnostic messages, and the level of
verbosity is controlled with the `--diagnostics` option, which takes
an argument that can be one of "fatal", "error", "warning", "info", or
"debug", the default being "info".

## Creating a request

To create, and sign, a new an add-leaf request, use the `-k` option to
pass a signing key. The message(s) to sign are listed as file
arguments on the command line, or, by default, read from standard
input. By default, the message submitted to the log is the SHA256 hash
of the input. To use the input as is, without hashing, pass the
`--raw-hash` option. In this case, the input data must either be
exactly 32 octets, or a hex string representing 32 octets (64 digits,
possibly with some leading and trailing whitespace).

If the request(s) are not to be submitted right away, as described below,
they are written to the respective output file(s), as described above.
Any existing output files are overwritten.

## Submitting a request

To submit one or more the leaf requests, specify a Sigsum policy file
using the `-p` option.

If the `-k` option and a signing key was provided, the leaf(s) to be
submitted are the newly created ones. If no `-k` option was provided,
each input should instead be a the body of an add-leaf request, which
is parsed and verified. Separating signing and submission is useful if
the machine with access to the signing key is not directly connected
to the Internet.

The policy file must specify a public key and URL for at least one log.
If the policy file specifies a quorum different from "none" and
corresponding witness public keys, `sigsum-submit` will not be
satisfied until it has retrieved enough valid cosignatures to satisfy
the quorum.

If the policy file specifies URLs for more than one log, they are
tried in random order.

If the log(s) used are configured to apply domain-based rate limiting
(as publicly accessible logs are expected to do), the
`--token-key-file` option must be used to specify the private key used
for signing a submit token, and the `--token-domain` option specifies
the domain (without the special "_sigsum_v1" label) where the
corresponding public key is registered. An appropriate "sigsum-token:"
header is created and attached to each add-leaf request.

When the inputs are provided on the command line (i.e., not read from
standard input), `sigsum-submit` first checks if the corresponding
output ".proof" file already exists. If it does exist, the proof is read
and verified; if the proof is valid, the corresponding input is
skipped, if it is not valid, `sigsum-submit` exits with an error. This
way, if a `sigsum-submit` call to submit a batch of requests fails
half-way for any reason, exactly the same command can be rerun and it
will process only the requests for which proofs are still missing.

When submitting a request, `sigsum-submit` repeats the request until
it is acknowledged by the log. It keeps polling the log until it has
collected all the pieces for a [Sigsum proof](./sigsum-proof.md),
i.e., a cosigned tree head, with cosignatures satisfying quorum
requirements, and an inclusion proof for the submitted leaf.

If submission to the first log fails, or polling for the required proof
material times out, `sigsum-submit` tries the next log.

On submission success, the Sigsum proof is written to respective
output file, as described above.

## Verifying a leaf request

If neither a signing key (`-k`) or policy file (`-p`) is provided,
`sigsum-submit` reads the leaf request(s) on the command line (or from
standard input if there are no arguments). Syntax and signature of
each leaf request is verified, but there is no output, just the exit
code to signal success or failure.

## Examples

To submit to the log server at `poc.sigsum.org`, we first need a
policy file with the following two lines.
```
log 154f49976b59ff09a123675f58cb3e346e0455753c3c3b15d465dcb4f6512b0b https://poc.sigsum.org/jellyfish
quorum none
```

Submit a message to this log.
```
$ echo "Hello old friend" | sigsum-submit -k example.key -p example.policy
version=0
log=c9e525b98f412ede185ff2ac5abf70920a2e63a6ae31c88b1138b85de328706b
leaf=9c30 5aa7e6233f9f4d2efbeb9eeef766dce8ba2aa5e8cdd3f53da94b5d59e67d92fc 40160c833571c121bfdc6a02006053a80d3e91a8b73abb4dd0e07cc3098d8e58a41921d8f5649e9fb81c9b7c6b458747c4c3b49cc08c869867100a7f7be78902

size=3
root_hash=5b0cc467f86fdd57b371e434843b571a4cb47c6a64dad4bc80d96dd7d15c63a9
signature=f6a87ce27a6df207eaaee6589ab73ac8cb5bead7bd0c0fea65556d847d11f3baea8ebdc686730f64e38000c77f5327048e73e08b7dc4de04b91f65930bedc100

leaf_index=2
node_hash=ede77b77a3bba27ea0af640d37e58281aef4459d71afdf5cf442cee8f9bebf5d
```

We can also do the submission in two steps. First create a requests,
saving it to "example.req".
```
$ echo "Hello again" | sigsum-submit -k example.key | tee example.req
message=07305a3200629a7b8a04f77008fa1b1f719fec3b60d4fdf2683ba60cf2956381
signature=aa5bd628d88be12d4f09feefe4bf65290b03bdeba8523fa38e396218140d79e0850132082914b08876cdc4a6041be8217402a57bfb8328310ad5407bc440060e
public_key=e0863b18794d2150f3999590e0e508c09068b9883f05ea65f58cfc0827130e92
```

Then submit it to the log.
```
$ sigsum-submit -p example.policy < example.req
version=0
log=c9e525b98f412ede185ff2ac5abf70920a2e63a6ae31c88b1138b85de328706b
leaf=a2ee 5aa7e6233f9f4d2efbeb9eeef766dce8ba2aa5e8cdd3f53da94b5d59e67d92fc aa5bd628d88be12d4f09feefe4bf65290b03bdeba8523fa38e396218140d79e0850132082914b08876cdc4a6041be8217402a57bfb8328310ad5407bc440060e

size=4
root_hash=fd23842c67ba396cbabaa22226f3cd7737a4cc9f36c897f4fce2cc5070925dc2
signature=fb573c4365ddc71110724f40dcbda62324d5c9b8e92d9e7cbda056f4c8e45e17018e72484c9d5af6e7c38b9705ed504375c3a03c7acc5abc3827dd042d1fe100

leaf_index=3
node_hash=4b3f8b78ae7fb7e6f6925d8a6f66af4d30de9b3e3a3f66cd4b0dba2c6b5b8725
node_hash=ede77b77a3bba27ea0af640d37e58281aef4459d71afdf5cf442cee8f9bebf5d
```

We can also verify the signature on the leaf request created above.
```
$ sigsum-submit < example.req
```

# The `sigsum-verify` tool

The `sigsum-verify` tool verifies a Sigsum proof, as created by
`sigsum-submit`.

The message to be verified is read from standard input. Like for
`sigsum-submit`, by default the message is the SHA256 hash of the
input data. If the `--raw-hash` options is provided, the input is used
as is, without hashing, and in this case, it must be either exactly 32
octets, or a hex string representing 32 octets.

The submitter's public key (`-k` option) and a policy file (`-p`
option) must be provided, and the name of the proof file is the only
non-option argument.

The proof is considered valid if

1. the submitter's signature on the message is valid,
2. the tree head is signed by one of the logs listed in the
   policy,
3. there are enough cosignatures to satisfy the policy's quorum
   requirement, and
4. the inclusion proof ties the leaf to the signed tree head.

See [Sigsum proof](./sigsum-proof.md) for more information on the
meaning of a sigsum proof, and the validation criteria,

## Example

Verify the proof from the first `sigsum-submit` example above,
assuming the proof has been saved to the file "example.proof".
```
$ echo "Hello old friend" | sigsum-verify -k example.key.pub -p example.policy example.proof
```

# The `sigsum-token` tool

The `sigsum-token` tool is used to manage the Sigsum "submit tokens"
that are used for domain based rate limiting (as defined in the
[Sigsum
spec](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md),
see also [rate limit
configuration](https://git.glasklar.is/sigsum/core/log-go/-/blob/main/doc/rate-limit.md)).
There are three sub commands, `record`, `create` and `verify`. The
`record` sub command is useful when setting up the DNS record that is
required for submitting to a log server with rate limits.

The other two sub commands are more obscure, and are intended for
scripts that need to handle submit tokens manually, e.g., to submit an
add-leaf request without using the `sigsum-submit` tool.

Using submit tokens requires a signing key, and it is recommended to
create a separate key used exclusively for this purpose.

## Creating a DNS record for a key

To use submit tokens, the corresponding public key must be registered
in DNS. The `sigsum-token record` sub command formats an appropriate
TXT record, in zone file format.

There's one mandatory argument, `-k`, specifying the public key to
use. The TXT record is written to standard output, or to the file
specified with the `-o` option.

## Creating a submit token

A token is a fix string, to be included in the "sigsum-token:" header
in `add-leaf` requests sent to a log. One can use the same rate limit
key with multiple logs, but tokens will be distinct, since they're
essentially a signature on the log's public key.

To create a token, use `sigsum-token create`. There are two mandatory
options, `-k` to specify the signing key, i.e., the private half of the
rate limit keypair, and `--log`, to specify the file with the log's
public key. If no other options are used, the output is the token in
the form of a hex string (representing an Ed25519 signature).

If the `--domain` option is used, the argument to this option is the
domain where the corresponding public key is registered, and then the
command outputs a complete HTTP header line.

Note that when using `sigsum-submit`, you don't need `sigsum-token` to
create any tokens; `sigsum-submit` creates appropriate tokens for each
log if you pass the `--token-key-file` and `--token-domain` options.

## Verifying a submit token

The `sigsum-token verify` sub command reads the token to validate from
standard input, and it handles both raw hex tokens, and complete HTTP
headers. For a raw token, one of `-k` (public key) or `--domain` is
required. For a HTTP header, `--key` and `--domain` are optional, but
validation fails if they are inconsistent with what's looked up from
the HTTP header. The `-q` (quiet) option suppresses output on
validation errors, with result only reflected in the exit code.

## Examples

Format a public key as a TXT record.
```
$ sigsum-token record -k example.key.pub
_sigsum_v1 IN TXT "e0863b18794d2150f3999590e0e508c09068b9883f05ea65f58cfc0827130e92"
```

Create a token, formatted as a HTTP header.
```
$ sigsum-token create -k example.key --log poc.key.pub --domain test.example.org
sigsum-token: test.example.org 327b93c116155a9755975a3a1847628e680e9d4fb1e6dc6e938f1b99dcc9333954c9eab1dfaf89643679a47c7a33fa2182c8f8cb8eb1222f90c55355a8b5b300
```
