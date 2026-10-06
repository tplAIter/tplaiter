# Provider session control acceptance

The installed local provider carrier owns a fixed acquisition-relative expiry.
Connection and registration selection consume that same deadline. Before the
carrier is returned, its socket deadline and close timer are armed. A caller
may select an earlier read or write deadline; clearing a deadline or selecting
a later one cannot extend the installed expiry. Expiry closes the connection
and held namespace descriptors, and expired reads, writes and rechecks return
`context.DeadlineExceeded`. Explicit Close is idempotent and stops the timer.
Earlier caller deadlines can time out one operation before the fixed lifetime.
Writes can have delivered bytes before expiry; a terminal error does not claim
that a partially delivered request was never received.

The neutral client refuses unsupported optional operations before dispatch;
those operations are not new global requirements for Open. Active cancellation,
partial responses, blocked request writes, deadlines, incompatible response
versions and peer refusals cannot yield a successful optional-operation receipt.
Terminal protocol and transport faults close the session. Unsupported optional
operations leave an otherwise compatible catalog/read session available.

Processing remains serial. The provider writes one complete response before
reading the next request, uses one bounded read-ahead buffer, and has no worker
queue. A blocked transport cannot promise a terminal error frame. Cancellation
is owned context/transport cancellation, not a permission-bearing request field.
Limits remain bounded bytes and frames; they do not certify model token capacity.

The lifetime tests use connected descriptor pairs without a listener. The client
fault tests use freshly authored neutral in-memory peers. These are finite
control proofs, not installed private-provider fault runs, source signatures or
organization qualification. Existing positive installed evidence is separate.
Local preview remains local-untrusted-observed with unchecked serving-code
identity and no source, publisher or organization authentication. Linux local
preview remains unavailable. Authenticated external context and organization
runtime acceptance require their own genuine admitted source and host evidence.
