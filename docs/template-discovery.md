# Template discovery

`tplaiter repo add`, `repo update`, `template list`, `lint-template` and
`init-template` share one discovery routine (`repo.DiscoverTemplatePaths` in
`internal/repo/scan.go`). It decides which directories of a template
repository are templates and enforces path confinement.

## Discovery roots

| Repository layout | Discovery roots |
|---|---|
| `repo.manifest.yaml` with `templates[]` | each `templates[].path` (authoritative; the root manifest, if any, is not indexed unless a root is `.`) |
| `repo.manifest.yaml` with no `templates[]` | the repository root |
| no `repo.manifest.yaml` | the repository root |

Every root is searched **recursively** for `template.manifest.yaml`, so a
provider repository with a root template and nested templates is indexed as a
whole:

```text
template.manifest.yaml                                    # provider-base  (path ".")
templates/worker/template.manifest.yaml                   # worker         (path "templates/worker")
bootstrap/template-repository/templates/service/template.manifest.yaml
                                                          # service        (path "bootstrap/template-repository/templates/service")
```

`testdata/fixtures/nested-provider` is the reference fixture for this shape.

Discovery skips hidden directories (including `.git`), `vendor`,
`node_modules`, `cache` and `target`, and does not search deeper than
`MaxDiscoveryDepth` (8) directory levels below a root. Directory symlinks are
never followed while walking. Results are sorted by path, and the index is
sorted by template name, then path.

A declared root that exists but contains no template manifest is an error.

## Tags

A template at the repository root of a repository **without**
`repo.manifest.yaml` keeps legacy single-template tags (`v1.2.3`). Every other
template, nested or declared, uses namespaced tags (`<name>/v1.2.3`), for
example `service/v0.1.0`.

## Confinement and typed errors

`templates[].path` is validated when `repo.manifest.yaml` is loaded, and again
against the filesystem during discovery. Failures are typed
(`manifest.RepositoryError`); the code is part of the error text so that
scripts and MCP clients can match on it.

| Code | Raised when |
|---|---|
| `TPL-E-REPO-PATH-ESCAPE` | `templates[].path` is absolute (including a drive letter) or contains a `..` segment; a declared root, one of its intermediate components, `repo.manifest.yaml` or a `template.manifest.yaml` is a symlink that resolves outside the repository |
| `TPL-E-REPO-DUP-PATH` | two `templates[].path` entries name the same directory, literally after normalization (`a`, `a/`, `./a`) or through a symlink |
| `TPL-E-REPO-DUP-NAME` | two discovered templates declare the same `metadata.name` (always fatal, including `repo update`) |
| `TPL-E-REPO-PATH-INVALID` | an empty or backslash-separated path, a missing or non-directory root, a root inside an excluded directory, a declared root without any template, or an unresolvable manifest symlink |

Symlinks that stay inside the repository are allowed. A declared root that is
a symlink is indexed under its **resolved** path, so the catalog never stores a
symlinked template path. A symlinked `template.manifest.yaml` whose target is
inside the repository indexes the directory that contains the symlink. The
repository root itself is resolved first, so clones reached through symlinked
parents (for example `/var` → `/private/var` on macOS) work.

`repo add` fails atomically on any of these errors: the repository is not
registered and its clone is removed. `repo update` skips a template whose
manifest is broken, with a warning, but confinement and duplicate errors
still fail the update.

## lint-template and init-template

- `lint-template` lints every discovered template. The root template is
  reported under the directory name; nested templates are reported under
  their repository-relative path. Duplicate names fail the lint with
  `TPL-E-REPO-DUP-NAME`.
- `init-template` verifies that the generated repository is discoverable
  (one template at `.`, or at `<name>/` with `--multi`). When the target
  directory is inside an existing template repository (the nearest ancestor
  with `template.manifest.yaml` or `repo.manifest.yaml`, bounded by `.git`),
  it refuses a name that the enclosing repository already declares
  (`TPL-E-REPO-DUP-NAME`) before writing any file.
