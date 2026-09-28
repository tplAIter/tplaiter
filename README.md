<p align="center">
  <img src="https://raw.githubusercontent.com/tplAIter/.github/main/assets/banner.png?v=20260928" alt="tplAIter — Build with blocks. Spend fewer tokens." width="100%">
</p>

<h1 align="center">tplAIter</h1>

<p align="center">Composable template blocks and validation for AI-assisted product development.</p>

<p align="center"><strong>Status: private development preview · not a release</strong></p>

<p align="center"><a href="https://github.com/tplAIter/template-base">base template</a> · <a href="https://github.com/tplAIter/template-go">Go template</a> · <a href="https://github.com/tplAIter/template-rust">Rust template</a> · <a href="https://github.com/tplAIter/docs">docs</a> · <a href="./docs/STATUS.md">status</a> · <a href="./docs/template-validation.md">template validation</a> · <a href="./docs/graph-explorer.md">graph explorer</a></p>

`tplaiter` is a Go command-line tool for working with template repositories and rendered projects. It preserves Go's `text/template` engine; template processing does not require a Python runtime.

## The intended workflow

An agent should not have to retype a service layout from scratch. Describe the
intent, ask an MCP tool for parameterized template blocks, compose them, then
validate the rendered result and its architecture. That gives local and
budget-conscious models a reviewable structure to work from, while frontier
models can spend more of their effort on product decisions.

```text
Intent: "Add a Go orders API with PostgreSQL and a worker"
  → MCP request: select parameters and blocks
  → template blocks: service, repository, transport, worker
  → validation: manifest, rendered project, language checks
```

This is the development direction, not a statement that the live CLI or MCP
workflow is complete today. The fixed lifecycle adapters needed for ordinary
`new` and `update` remain unavailable in this preview.

## What is here

- A Go 1.26+ CLI and the existing template processing engine.
- Manifest, schema, repository, statistics, and template validation packages.
- A reusable GitHub Action for linting `template.manifest.yaml` and rendering fixture projects.
- A local graph and context explorer (`cmd/graphview`) with provenance-aware views and bounded context packs.
- Trust and lifecycle building blocks under active engineering review.

### Evaluation targets, not measured results

We are targeting 30% fewer coding and retrieval tokens through reusable,
parameterized blocks. Reliability and maintainability remain qualitative goals
until they have a defined evaluation method.

Published template repositories are intended to use the shared checker, then run their generated-language checks in the caller workflow. The checker validates the manifest and rendered files without running template hooks, manifest commands, or reading credentials.

## Checkpoint status

This is a private development preview. It has no published release, compatibility promise, production support commitment, or production-installed trust anchors.

The ordinary live `new` and `update` paths are unavailable until their fixed adapters are complete. A stock CLI stops those paths with `TRUST_ANCHOR_MISSING`; registering an anchor does not make the live lifecycle available and still leads to `TRUST_LIFECYCLE_UNAVAILABLE`. Fixed simulated registration tests cover dry-run and maintenance behavior, but they do not establish production provisioning or an end-to-end lifecycle.

Focused internal package checks cover template initialization, contribution, settings, statistics, repositories, and table rendering. The separate black-box lifecycle module remains a known limitation. Windows builds also require platform work for existing Unix-specific references in `execx` and `naming`.

## Local verification

With Go 1.26 or newer and the module dependencies available, run focused checks such as:

```sh
go test ./cmd/graphview ./cmd/templatecheck
go test ./internal/contextpack ./internal/graphview
```

The complete suite depends on the available module cache and checkpoint state; these focused commands are the small local checks shown here, rather than a claim that every package is production-ready. The validation workflow and its safety boundaries are documented in [template validation](./docs/template-validation.md).
