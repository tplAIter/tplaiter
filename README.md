<p align="center">
  <img src="https://raw.githubusercontent.com/tplAIter/.github/main/assets/banner.png" alt="tplAIter — Templates for the way you build." width="100%">
</p>

# tplAIter

`tplaiter` is a Go command-line tool for working with template repositories and
rendered projects. It uses Go's `text/template` engine; the project does not
require a Python runtime for template processing.

## Checkpoint status

This checkpoint is an in-progress engineering snapshot, not a release.
It contains the rehomed core module, its schemas, embedded template skeletons,
and the applicable test fixtures. The repository is being prepared as a clean
new history after privacy and provenance review.

The command surface, template packages, trust workflows, and publication
metadata are still under active development. Project creation and update
action paths are unavailable until their fixed adapters are complete. Do not
rely on this checkpoint for production use or compatibility guarantees.

The CLI has no production-installed trust anchors in this checkpoint. A stock
CLI stops `new` and `update` with `TRUST_ANCHOR_MISSING`; registering an anchor
does not enable ordinary live project creation or update until the fixed
adapters are complete, so those paths still stop with
`TRUST_LIFECYCLE_UNAVAILABLE`.

Fixed simulated registration tests cover dry-run and maintenance behavior.
They do not constitute production provisioning or a working end-to-end project
lifecycle claim. Focused internal package checks currently pass for template
initialization, contribution, settings, statistics, repositories, and table
rendering. The separate black-box lifecycle module remains a known limitation
because it exercises ordinary live creation and update. Windows builds are not
ready for this checkpoint because existing Unix-specific references in `execx`
and `naming` still require platform work.

## Local verification

Use Go 1.26 or newer. The intended offline verification environment is:

```sh
env -u TPLATER_HOME -u TPLAITER_HOME \
  HOME=/var/tmp/tplaiter-checkpoint GOPROXY=off GOSUMDB=off \
  go test ./...
```

The command is run only after the active core changes have been frozen into the
checkpoint.
