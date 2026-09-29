# State-ledger fixtures

Portable, credential-free fixtures for `internal/stateledger`.

- `v1/project.yaml` is the minimal legacy `tplater.dev/v1alpha1` marker used by
  the pure migration tests.
- `v1/project/.tplaiter` contains every project ledger named by the ledger
  classification table (`internal/stateledger/ledgerpath`), plus an opaque
  file, an update lock, an update CAS entry and a rebuildable graph cache.
  The provenance v2 root and dependency locks are written by the tests from
  the sealed fixture root so their digests are always self-consistent.
- `v1/home` contains a registry, config, index, run state, trust cache and
  the global `new.lock`. Global new-transaction journals (active, complete,
  future, missing-CAS) are created by the tests with the real transaction
  engine, because a valid journal binds absolute paths and CAS blobs.
- `v1/golden` holds byte-exact goldens: canonical JCS bytes followed by one
  newline. They are regenerated only by hand after reviewing the diff.

Tests copy the fixture into a temporary root and create synthetic secret
placeholders there; nothing here is a real credential. Hosts use
`example.test`.

The repository `.gitignore` ignores local `.tplaiter/` state directories, so
the fixture state directory is tracked explicitly (`git add -f`). Remember
`-f` when adding a new fixture ledger there.
