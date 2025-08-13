# What is a Sigsum proof?

In short, a "sigsum proof" is a proof of public logging, which is
distributed and verified in a similar way as a detached signature (as
created by, e.g., `gpg --detach-sign`). This document describes the
contents of such a proof, and the corresponding steps needed to verify
it.

## Example use case

To take a step back, the idea is that one party, the *submitter*,
wants to distribute a message together with proof that the message is
publicly logged. See
[design](https://git.glasklar.is/nisse/cats-2023/-/blob/main/sigsum-design-cats-2023.pdf)
for the bigger picture on why that is useful. The submitter interacts
with a sigsum log server to submit the message, and collect related
inclusion proof and cosignatures. This is packaged, together with
the message and any associated data, to be distributed to a *verifier*.

As concrete usecase, consider distribution of software updates. Then
the logged message is the hash of a software update. The update
and the sigsum proof is distributed to the devices to be updated. The
software update client then uses the sigsum proof to determine whether
or not the update should be installed.

# Syntax/serialization

In principle, each application can choose its own representation,
e.g., if a sigsum proof is incorporated inside a future version of a
binary debian package. The intention of this document is to both
describe the parts that must be included in a sigsum proof, regardless of
representation, and specify the particular format that is used by the
sigsum commandline tools.

## Ascii representation

Building on the [ascii
format](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md)
used on the wire when interacting with a sigsum log, we defined the
following ascii format for a sigsum proof. It includes a version
number, currently 2, the keyhash identifying the log that was used,
the recorded Sigsum leaf (but without the checksum), a cosigned
tree head, and an inclusion proof. An empty line, i.e., double
newline character, separates the distinct parts.

```
version=2
log=KEYHASH
leaf=KEYHASH SIGNATURE

tree_size=NUMBER
root_hash=HASH
signature=SIGNATURE
cosignature=KEYHASH TIMESTAMP SIGNATURE
cosignature=...

leaf_index=NUMBER
node_hash=HASH
node_hash=...
```

The version line specifies the version of the proof format, and will
be incremented as the format is changed or extended. The `log` line
identifies the sigsum log. In the next line, `leaf` is similar to the
response to the `get-leaves` request, but the checksum is omitted; the
checksum must be derived from other context.

The last two blocks are verbatim responses from the get-tree-head and
get-inclusion proof requests (in the corner case that `tree_size` = 1,
the last part is omitted, since it is implied that `leaf_index` = 0,
and there is no inclusion path).

# Verifying a proof

To verify a sigsum proof, as defined above, the verifier needs
additional information: It needs to know the message being logged (in
the software update usecase, `message = H(file)`, where `file` is the
update package to possibly be installed). The verifier also needs the
submitter's and the log's public keys, as well as public keys for some
witnesses.

To verify the proof, the following steps are required:

1. Compute `checksum = H(message)`.

2. Check that the leaf keyhash equals the hash of the submitter's
   public key, and that the log keyhash equals the hash of a
   recognized log's public key. (Requiring bitwise equality defends
   against attacks involving multiple equivalent representations of
   public keys).
   
3. Check that the leaf signature (with `checksum` computed as above)
   is valid.
   
4. Check that the log's tree head signature is valid.
   
5. Verify all cosignatures for witnesses known to the verifier. Which
   subsets of witnesses are considered strong enough, is determined by
   application policy. One possible policy is to require k valid
   cosignatures out of n known witnesses; more complex policies are
   possible but out of scope for this document.
   
6. Compute the `leaf_hash` from the `checksum` together with the
   keyhash and signature from the leaf line, and check that the
   inclusion proof is valid. In the corner case that `tree_size = 1`,
   instead check that `leaf_hash = root_hash`.

## Use of timestamps

Each cosignature timestamp is covered by the corresponding witness
cosignature, and hence are required to be able to verify the
cosignature. However, after a cosignature has been verified, the
timestamp value is ignored by the above verification procedure.
Application policy may apply additional constraints on the timestamps.

# Notes on the previous version 1 of the Sigsum proof format

The format above is the second iteration of the proof format. The
previous version differed in the first line, which said `version=1`,
and the third line, which used the format

```
leaf=SHORT-CHECKSUM KEYHASH SIGNATURE
```

The additional field was 4 hex digits, encoding the first 16 bits of
the checksum. The only purpose of this short checksum was to enable a
clearer error message if by accident a proof file was applied to the
wrong data. A proof verifier was expected to compare the short
checksum in the proof to the checksum of the message being verified,
before attempting to verify the leaf signature. See [proposal][] for
the rationale for removing this field.

[proposal]: https://git.glasklar.is/sigsum/project/documentation/-/blob/main/proposals/2024-11-proof-with-no-leaf-checksum.md


