# Template validation

Published template repositories run the shared `template-check` composite action
from the core repository. The action validates `template.manifest.yaml`, runs
the existing `inittemplate.Lint` combinations, and renders each combination
into an empty directory owned by the runner.

The checker uses the existing Go template engine. It does not install tools,
run template hooks, execute manifest commands, or read credentials. A source
root or source-tree symlink is rejected before parsing. Output roots must be
empty runner-owned directories, cannot be symlinks, and are canonicalized before
the checker verifies they are outside the source tree. The render fixture uses
the stable coordinates `CI Fixture`, `ci_fixture`, `example.com/ci_fixture`,
system `ci`, domain `ci`, and port `8080`.

Consumer workflows should pin the action reference to the full reviewed commit
SHA. The action is intended for `push`, `pull_request`, and `workflow_dispatch`
events. Generated consumer checks (for example `go test ./...` or
`cargo test --all-targets`) run in the caller workflow after this action and are
separate from template lint/render. No release, deployment, or
`pull_request_target` workflow is part of this validation contract.

The Rust consumer workflow pins its validation toolchain to Rust 1.98.0. That
CI pin does not establish or claim a minimum supported Rust version for the
generated template.

The checker currently validates the template manifest and rendered files. It
does not claim generator validation when a manifest has no generator
declarations.
