# Sigsum policy file

Documentation of how to specifying sigsum policy. 

## What is a "policy"

A sigsum policy includes three pieces of information.

 * A set of known logs.

 * A set of known witnesses.

 * The quorum: the rule that determines whether or not a subset of
   witnesses that have cosigned a tree head is strong enough to
   consider the tree head to be valid.

Both logs and witnesses are identified primarily by their respective
public key. Each log or witness may also have an associated URL; this
is required for operations interacting with the log or witnesses, but
no URLs are needed if the policy is used only for offline
verification.

Witnesses also have a name. These names are used only for referencing
the witnesses in the definition of the quorum; they have no meaning
outside of the policy file itself.

## Policy file syntax

The policy file is line based, where each line consist of items
separated by white space. Comments are written with "#" and extend to
the end of the line. With one exception regarding names, the order of
lines doesn't matter. In particular, the order of logs or witnesses
does not imply any preference or priority.

Public keys are written in raw hex representation. The `sigsum-key
hex` can be used to convert a public key in openssh format to raw hex,
and `sigsum-key hex-to-pub` for the opposite conversion.

### Defining a log

A log is defined by a line 
```
log <pubkey> [<url>]
```
When the policy is used for verifying a sigsum proof, all of the
listed logs are accepted. When the policy is used for submitting a new
entry to a log, any of the logs that has an associated URL can be
used. The `sigsum-submit` tool tries them in randomized order, until
logging succeeds.

### Defining a witness

A witness is defined by a line
```
witness <name> <pubkey> [<url>]
```
Since only logs and possibly monitors interact directly with
witnesses, most policy files will not need and witness URLs (and some
witnesses may not have any publicly accessible URL at all). The name
is used to refer to this witness when defining the quorum, or when
defining witness groups (see below).

### Defining the quorum

The quorum is defined by a line
```
quorum <name>
```
In the simplest case, the name refers to a witness, and it means that
a cosignature from that witness is required for a tree head to be
considered valid. Here's the exception to the rule that order of
lines doesn't matter: A name must be defined on a line that precedes
the line where the name is referenced.

To not require any cosignatures a all, one can use the predefined name
`none`, like
```
quorum none
```
To define more complex quorums, the name can also refer to a witness
group, the next topic. 

A policy file must include exactly one quorum line. TODO: Make quorum
line syntactically optional, i.e., don't fail when parsing a policy
with no quorum; only fail later if the policy is used to verify a tree
head, e.g., the `policy.VerifyCosignedTreeHead` would fail.

### Defining witness groups

Defining a witness group is useful for constructing more complex
quorums. A group is defined by a line of one of these forms:
```
group name all <name>...
group name any <name>...
group name <k> <name>...
```
All these defines a group, where the group acts as a witness if and
only if at least k of its n members acts as a witnesses, each group
member being either a witness or another group. In this terminology,
that a single witness "acts" means that it has signed a valid
cosignature.

Like on the quorum line, a group definition can only refer to names
defined on preceding lines, in particular, there can be no circular
group definitions.

The `any` variant is a shorthand for k = 1, and the `all` variant is a
shorthand for k = n.

## Example policy

This is an example of a policy with quorum defined using two levels of
groups. Actual keys are elided, for brevity:
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
This quorum definition means that when verifying a cosigned tree head
(e.g., as part of verifying a sigsum proof, using the `sigsum-verify`
tool), it is required that there are valid cosignatures from at least
two of the X witnesses, and from at least one of the Y witnesses.
