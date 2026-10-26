# Read-only process collection

`collect_process(pid, access=...)` queries executable path, parent chain (nearest
parent first, with each PID, creation time, name and path), command-line argument
list, UTC start time, user, IPv4/IPv6 connection endpoints and statuses, and all
available per-process I/O counters. Connections are a snapshot, not a traffic
history; counters are cumulative since process creation and are not disk rates.
No executable is launched and no target process is controlled.

The subject ID is `<pid>:<repr(creation_time)>`, preserving psutil's full float
precision. Reads check identity before and after querying to discard observations
when the PID is reused. A parent chain that cannot be completed is unavailable;
it is never reported as an observed empty chain. Traversal is limited to 128
ancestors and rejects cycles and parents newer than their child.

Each field is collected independently. Access denial, process exit and timeouts
produce unavailable evidence with fixed reason codes; other expected OS failures
produce error evidence. A failure reading creation time instead returns a
structured `CollectionError` with PID, availability and reason, without inventing
an EvidenceBundle identity. Evidence content is untrusted data.

`ProcessAccess` is the mockable read-only interface. `PsutilAccess` implements it
with [psutil queries](https://psutil.readthedocs.io/en/release-7.2.2/).

## Executable SHA-256

`collect_hash` streams the executable in 1 MiB chunks, with a default 256 MiB
size limit and a five-second timeout (including helper startup). Limits are
configurable through `HashLimits`. A dedicated Python helper bounds even a
blocked open/read call; the target executable is only opened in binary read mode.
The timeout may stop that owned helper, never the investigated process.

The worker checks the actual byte count and file metadata before and after the
read. Oversized, changing, inaccessible or missing files produce unavailable
evidence. No partial digest is returned. Successful values include SHA-256 and
the size, modified time in nanoseconds, device and inode of the hashed file.
`HashAccess` and `CommandRunner` allow tests to replace file and subprocess calls.

## Digital signatures

`SignatureCollector` uses Windows PowerShell's
[`Get-AuthenticodeSignature -LiteralPath`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
in an argument-list subprocess with a five-second timeout. A constant encoded
script reads the UTF-8 literal path from stdin, so file names are never interpreted
as PowerShell code. Queries run without a profile or visible window.

Values contain a `state`: `signed_valid`, `signed_invalid`, `unsigned` or
`unavailable`. Valid maps to signed_valid; NotSigned to unsigned; HashMismatch,
NotTrusted and UnknownError with a signer certificate to signed_invalid. An
unsupported format, incompatible verifier or UnknownError without a signer is
unavailable. Malformed replies are error evidence. Missing paths, hashes, tools,
permissions and timeouts retain a reason and unavailable state.

An LRU cache stores up to 128 observed results per collector instance, keyed by
file hash, modified time in nanoseconds and literal path (catalog signatures may
be path-dependent). Metadata must match the hashed file before and after each
query or cache hit. Failures are not cached. Cache lifetime is the collector
instance's lifetime; create a fresh collector to refresh Windows trust results.
Metadata checks detect ordinary file changes, not an adversarial replacement
that preserves all metadata. A signature observation is not a safety verdict.
`SignatureAccess`, `MetadataAccess` and `CommandRunner` are injectable boundaries.
