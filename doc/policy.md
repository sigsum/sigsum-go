# Sigsum policy file

Documentation of how to specifying sigsum policy. 

## What is a "policy"

A sigsum policy includes three pieces of information.

 * A set of known logs.

 * A set of known witnesses.

 * The quorum: the rule that determines whether or not a subset of
   witnesses that have cosigned a tree head is strong enough to
   consider the tree head to be valid.

The policy can be used and enforced by several of the sigsum roles,
but the most important use is for verifying a [sigsum
proof](./sigsum-proof.md). The policy says that a tree head is
considered valid if it is signed by any one of the listed logs, and it is
cosigned according to the defined quorum rule.

Both logs and witnesses are identified primarily by their respective
public key. Each log or witness may also have an associated URL; this
is required for operations interacting with the log or witnesses, but
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
witness Y2 <key>
group Y-witnesses any Y1 Y2 Y2

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

The policy file is line based, where each line consist of items
separated by white space. Comments are written with "#" and extend to
the end of the line.

Public keys are written in raw hex representation. (The `sigsum-key
hex` command can be used to convert a public key in openssh format to
raw hex, and `sigsum-key hex-to-pub` for the opposite conversion.)

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

### Defining a witness

A witness is defined by a line
```
witness <name> <pubkey> [<url>]
```
Since only logs and possibly monitors interact directly with
witnesses, most policy files will not need any witness URLs. The name
is used to refer to this witness when defining the quorum, or when
defining witness groups.

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

A policy file must include exactly one quorum line. TODO: Make quorum
line syntactically optional, i.e., don't fail when parsing a policy
with no quorum; only fail later if the policy is used to verify a tree
head, e.g., the `policy.VerifyCosignedTreeHead` would fail.
Potentially useful for log server policy, since a log server needs
public keys and urls for witnesses, but has no need for a quorum to
verify its own tree heads.

### Defining a witness group

Defining a witness group is required for defining a quorum that is not
a single witness. A group is defined by a line of one of these forms:
```
group <name> all <name>...
group <name> any <name>...
group <name> <k> <name>...
```

All these defines a group, where the group is considered to witnes a
tree head if and only if at least k of its n members have witnessed
that tree head, each group member being either a witness or another group.
In this terminology, for a single witness, "witnessing" is the same as
cosigning.

Like for the quorum definition, a group definition can only refer to
names defined on preceding lines. (This also rules out circular group
definitions).

The `any` variant is a shorthand for k = 1, and the `all` variant is a
shorthand for k = n.
