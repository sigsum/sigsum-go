# Sigsum policy file

## Introduction

This document specifies the Sigsum policy file format. The policy can
be used and enforced by several of the Sigsum roles, but the most
important use is for verifying a [sigsum proof](./sigsum-proof.md),
e.g., using the `sigsum-verify` tool. In addition, a policy file is
also used by monitors, submitters, and log servers.

While the design is tailored for use with Sigsum, the main semantics
can be applied also to other transparency logs that rely on witness
cosigning. Please see Appendix A below for further recommendations on
this.


## What is a "policy"?

A Sigsum policy includes three pieces of information.

 * A set of known logs.

 * A set of known witnesses.

 * The quorum: the rule that determines whether or not a subset of
   witnesses that have cosigned a tree head is strong enough to
   consider the tree head to be valid.

The policy says that a tree head is considered valid if it is signed
by any one of the listed logs, and it is cosigned according to the
defined quorum rule.

Both logs and witnesses are identified primarily by their respective
public key. Each log or witness may also have an associated URL; this
is required for operations interacting with the log or witness, but
no URLs are needed if the policy is used only for offline
verification.

Witnesses also have a name. These names are used only for referencing
the witnesses in the definition of the quorum (directly, or indirectly
via group definitions); they have no meaning outside of the policy
file itself. We will look at an example policy, before specifying the
contents of the policy file in detail.

## Example policy

This is an example of a policy with a quorum defined using two levels of
groups. Actual keys are elided, for brevity, and the optional URLs are
omitted:
```
log <key>
witness X1 <key>
witness X2 <key>
witness X3 <key>
group X-witnesses 2 X1 X2 X3

witness Y1 <key>
witness Y2 <key>
witness Y3 <key>
group Y-witnesses any Y1 Y2 Y3

group X-and-Y all X-witnesses Y-witnesses
quorum X-and-Y
```
This policy file lists a single log and six witnesses. The witnesses
are divided into two groups, e.g, because the `X-witnesses` are
operated by one organization, and the
`Y-witnesses` are operated by a separate organization.

The number "2" in the definition of the `X-witnesses` is a threshold.
It means that if at least two out of these three witnesses have
cosigned (or "witnessed") a tree head, then the group is considered to
have witnessed that same tree head. The keywords "all" and "any" can be
used instead of a numeric threshold.

The quorum definition in this example means that when verifying a
cosigned tree head, it is required that there are valid cosignatures
from at least two of the `X-witnesses`, and from at least one of the
`Y-witnesses`, and this rule is represented by the group `X-and-Y`.

## Policy file syntax and structure

### Structure

The policy file is line based, where each line consist of items
separated by ASCII space and tab characters. Comments are written with
"#" and extend to the end of the line.

Public keys are written in raw hex representation. (The `sigsum-key
to-hex` command can be used to convert a public key in OpenSSH format to
raw hex, and `sigsum-key from-hex` for the opposite conversion.)

Lines defining witnesses and logs can appear in any order; the order
does not imply any preference or priority. A line defining a group can
only reference names of groups and witnesses defined on preceding
lines. Similarly, the quorum line must specify a witness or group
defined earlier.

### Defining a log

A log is defined by a line 
```
log <pubkey> [<url>]
```
When the policy is used for verifying a sigsum proof, all of the
listed logs are accepted. When the policy is used for submitting a new
entry to a log, any of the logs that has an associated URL can be
used. (The `sigsum-submit` tool tries them in randomized order, until
logging succeeds).

Duplicate logs, i.e., multiple log lines with the same public key, are
not allowed.

### Defining a witness

A witness is defined by a line
```
witness <name> <pubkey> [<url>]
```
Since only logs and possibly monitors interact directly with
witnesses, most policy files will not need any witness URLs. The name
is used to refer to this witness when defining the quorum, or when
defining witness groups.

Duplicate witnesses, i.e., multiple witness lines with the same public
key, are not allowed.

### Defining the quorum

The quorum is defined by a line
```
quorum <name>
```
In the simplest case, the name refers to a witness, and it means that
a cosignature from that witness is required for a tree head to be
considered valid.

To not require any cosignatures a all, one can use the predefined name
`none`, like
```
quorum none
```
To define more interesting quorums, the name can also refer to a witness
group, the next topic. In either case, the name must be properly
defined on a line preceding the quorum definition.

A policy file must include exactly one quorum line.

### Defining a witness group

Defining a witness group is required for defining a quorum that is not
a single witness. A group is defined by a line of one of these forms:
```
group <name> all <name>...
group <name> any <name>...
group <name> <k> <name>...
```

All these defines a group, where the group is considered to witness a
tree head if and only if at least k of its n members have witnessed
that tree head, each group member being either a witness or another group.
In this terminology, for a single witness, "witnessing" is the same as
cosigning.

The `any` variant is a shorthand for k = 1, and the `all` variant is a
shorthand for k = n.

Like for the quorum definition, a group definition can only refer to
names defined on preceding lines. (This also rules out circular group
definitions).

Each defined name can be listed as a member at most once. This ensures
that each witness can contribute to a group, or to the quorum in
particular, in only one way.

### Use of non-ASCII characters

The policy file syntax is based on ASCII characters. The only allowed
control characters are tab (0x09) and newline (0x0a). Non-ASCII
characters may appear in names, URLs and comments. Using UTF-8 for any
non-ASCII text is strongly recommended, but a policy file parser may
treat the items as opaque octet strings, with no attempt to reject
invalid utf-8 or inappropriate unicode characters.


## Appendix A: Use with non-Sigsum logs

This policy file format can be used for non-Sigsum logs. One important
usecase is to specify the quorum for verifying a
[cosigned](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md)
[checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md).

The Sigsum project would suggest for this case to:

* Apply each policy file to a single log origin line, configured
  separately.

* Avoid using log URLs (since it is expected that such URLs are usable
  with the Sigsum log API).

* Use witness names corresponding to the key names used in the
  corresponding checkpoint cosignature lines. This policy file syntax
  is liberal enough that all valid [key
  names](https://github.com/C2SP/C2SP/blob/main/signed-note.md#format)
  are valid witness names.

Further issues may be discovered, and a shared policy specification
may be developed in the future under the [C2SP
umbrella](https://github.com/C2SP/C2SP/tree/main).


## Appendix B: Use on constrained devices

It is desirable to be able to apply Sigsum policy as part of Sigsum
proof verification on constrained devices. A constrained device will
likely have to enforce some limits on policy complexity. It is
recommended that an implementations of Sigsum policy at least supports
up to 32 logs, 32 witnesses, and 32 groups.

For a constrained device it would also be helpful with a "compiled"
binary representation of the policy, that is compact, easy to parse,
and easy to apply; this may be subject to future specification.
