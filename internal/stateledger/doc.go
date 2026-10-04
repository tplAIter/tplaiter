// Package stateledger is the content-addressed inventory, verifier and
// migration planner for tplaiter project and home state.
//
// # Ledgers
//
// Every project ledger lives in the project state directory (StateDir,
// ".tplaiter"); the fixed set is StandardPointers. Home state lives in the
// tplaiter home. The classification of each path (kind, owner, retention,
// wire version, whether it belongs to a transaction engine) comes from the
// shared table in internal/stateledger/ledgerpath, which the global new
// transaction engine and `migrate-state` use as well.
//
// # API for lifecycle commands
//
// Read-only (safe for verify/check/deps verify; no file, cache or network
// write):
//
//   - Inventory(projectRoot, Options) lists the state directory and,
//     optionally, the home. Home files are classified by a
//     SecretDigestProvider before they are opened; credentials are never read.
//     Snapshot.Transactions carries the global new-transaction inventory
//     (active, complete, aborted, future, missing-cas, unsafe, orphan).
//   - VerifyStable(ctx, projectRoot, authority, StableVerifyOptions) checks a
//     project/v2 marker, every ledger pointer, the absence of unfinished
//     transactions, the provenance v2 root/dependency lock pair and its trust
//     profile binding, and (with a CAS) every referenced evidence object.
//   - VerifyDependencyLocks(ctx, projectRoot, authority, cas) is the narrow
//     lock-pair check behind `deps verify --offline`.
//   - Plan / PlanTarget build a sealed MigrationPlan from the v1alpha1 marker
//     to project/v2 (a no-op plan for v2, ErrDowngrade for anything older
//     than the current version, ErrFutureVersion for anything newer).
//
// The authority is a BindingAuthority, implemented by *trustverify.Runtime.
// VerifyStable additionally requires ProjectIdentityAuthority and checks the
// marker ID and canonical project root against a freshly authenticated installed
// context both before inventory and before returning. Profile-only authorities
// cannot fall back to marker identity; source-lock verification alone is narrower.
// The development runtime cannot satisfy it and a development binding is
// refused, so an unverified profile never vouches for stable state. The
// package does not import any policy-root or legacy trust package.
//
// Writers (used by new/update in U07):
//
//   - SealRootLock and NewDependencyLock build sealed provenance v2 locks. A
//     root without dependencies always gets an explicit `"dependencies": []`.
//   - WriteLockPair durably writes a validated pair, dependency lock first.
//   - ApplyPlan re-plans, requires the reviewed plan digest, and writes the
//     synthesized dependency lock and then the project/v2 marker (the commit
//     point).
//
// Legacy profileless v1 locks are refused with ErrLegacyLock: they must be
// re-resolved through the trust runtime by `update` before the ledger can
// accept them.
package stateledger
