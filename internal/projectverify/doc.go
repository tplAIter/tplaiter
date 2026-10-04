// Package projectverify verifies a prepared project using an already stable
// trust authority and read-only evidence. Verify and VerifyDependencies do not
// construct authority, resolve sources, refresh evidence or write state.
//
// Reports are derived from the canonical ledger byte/mode anchors, canonical
// lock-pair decoding, CAS digests and fresh project identity proof. Held-root
// no-follow observations reject nonregular files and bound each body to 16 MiB;
// projected anchors are rechecked after callbacks. This does not promise an
// atomic snapshot of the entire mutable project tree.
//
// Cancellation has a typed diagnostic and retains its context cause. At base
// fbdae445 the shared DTO has no cancellation exit; ExitCancelled uses the
// registered operational value 3. CLI/MCP wiring and any shared exit-registry
// change belong to the separate U08 owner, not this backend package.
package projectverify
