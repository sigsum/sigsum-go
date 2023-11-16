# Sigsum monitor

A Sigsum monitor is required to be able to detect, and hence act, on
unexpected or unauthorized signatures appear in a log. This file
documents the monitor program and corresponding library included in
sigsum-go.

## Cryptographic operations

For each log, the monitor repeatedly fetches the latest tree head, and
verifies the log's signature. (It should also verify cosignatures of
known witnesses, and use cosignature timestamps for freshness checks,
but that is not yet implemented). As the tree grows, the monitor asks
for all the new leaves, and corresponding inclusion proofs, to ensure
that it gets to see all leaves included in the log.

For each new leaf, the monitor compares the submitter's key hash with
the monitor's list of configured keys, and for keys that
match, the signature is varifies, and the leaf is output. As a special
case, it is possible to run the monitor with an empty list of
submitter keys; in that case, all new leaves are output, but without
any verification of leaf signatures.

## The sigsum-monitor program

This program can monitor one or several logs. It is configured with a
sigsum policy file, listing logs and witnesses, and a list of public
keys of interest.

It writes one line to standard out for each leaf carrying a signature
from one of the listed keys, and one line for each detected problem in
the log.

There are a few missing features: Witness cosignatures are not
processed at all (it is desirable to log an alert if a witness
disappears, or if too many witnesses disappears so that the policy
quorum isn't satisfied). The precise format of the output is not yet
stable or documented, it may also be useful with a mode with more
structured output, e.g., in json format.

### Invocation

The `sigsum-monitor` has one mandatory option, `-p`, specifying the
sigsum policy file, and a few optional options. It takes the list of
submitters' public key files as non-option command line arguments. The
options are: `--interval` for specifying how often to query logs for
new tree head, `--diagnostics` for specifying the level of diagnostic
output written to standard error, and `--state-directory` for
specifying a directory where the monitor's state is stored, so that it
can be stopped and restarted without starting over from the start of
the log.

## Monitor state

For each log, the monitor records the most recently seen tree head,
and the number of leaves that the monitor has downloaded and verified
(when a monitor is far behind a log, it processes leaves in smaller
batches).

TODO: Consider if it really makes sense to store the tree head
signature.

When the monitor's state is persisted to disk (using the
`--state-directory` option), the directory can hold one file per log,
with name being the lowercase hex hash of the log's key. The contents
of the file is an ascii-format signed tree head. Format is the same as
returned by the `get-tree-head` request to the log, see [sigsum
protocol][], except that there are no cosignature lines. This tree
head is followed by an empty line, and a line
"next_leaf_index=NUMBER".

[sigsum protocol](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md)

## Monitor go package

The corresponding go library, `sigsum.org/pkg/monitor` is work in
progress. The main parts are:

### Config

The `monitor.Config` defines the configuration shared between logs.
The submit keys to watch, the query interval and the batch size, and
most importantly, the application's `monitor.Callbacks` interface, see
below.

### Callback interface

The `monitor.Callback` interface includes call back functions invked by
the monitr when a new tree head is seen, when new leaves are seen, and
when any problems with the log are observed.

### MonitorLog

The `monitor.MonitorLog` function monitors a single log. This is a
blocking function, intended to be called in its own goroutine.

### StartMonitoring

The `monitor.StartMonitoring` takes a sigsum policy as input, and
spawns one monitoring goroutine for each log, and returns immediately.
It returns a channel, that is closed after monitor has been
terminated. To stop the monitoring from the application, first cancel
the passed in context, and then wait on that channel.
