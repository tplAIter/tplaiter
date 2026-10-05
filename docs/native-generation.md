# Native file generation

File-only native `gen`, `gen list` and `gen batch` are restored in [68899a0](https://github.com/tplAIter/tplaiter/commit/68899a059fa13ade3d0dab6f4143303edc2bf966), including their MCP counterparts. The guard that blocks incompatible operations while a native generation transaction is unfinished remains pending implementation and acceptance. This page describes the accepted file-only capability; it does not claim complete lifecycle safety, build or hook support, recovery CLI, or the broader live-update beta. The bounded signed native Update CLI and MCP candidate is documented separately in [native Update](native-update.md).

Use an installed, provisioned binary and a project created from an enrolled signed native template. Follow [installation](install.md) and [source enrollment](source-enrollment.md) first. A plain build without installation registration cannot generate files.

## Select the installed project

`--project-context` selects a key from the finite set approved during installation. It cannot register a new project or redirect an existing key. List the installed keys with:

```sh
tplaiter trust contexts --json
```

In the examples below, `a` is an installed key and `/absolute/canonical/projects/a` is its exact recorded root. Replace both with values from your installation.

`--dir` is an optional locator. Its absolute normalized path must equal that root; a symlink alias is not accepted. Omitting it uses the selected installed root. Omitting `--project-context` uses the installation's default key. Changing the working directory does not select a different project.

## List and generate

List the generators supplied by the project's signed template:

```sh
tplaiter gen list \
  --project-context a --dir /absolute/canonical/projects/a --json
```

Availability reflects the project's recorded settings. The CLI checks the installed project, its sealed state and retained generator resources. A local manifest, edited snippet, repository checkout or current directory cannot replace those inputs. Resolve a reported settings or resource mismatch through the supported project setup workflow; editing metadata to bypass it is not a remedy.

The public Go template snapshot at [d017954](https://github.com/tplAIter/template-go/tree/d0179547cd2e47b7564b0011bc5045799fc036bd) declares the `entity` generator. When that snapshot is enrolled and its project is created, generate an entity with:

```sh
tplaiter gen entity Ride \
  --project-context a --dir /absolute/canonical/projects/a \
  --no-build --json
```

This generator creates `internal/ride/types.go`, controller, service and repository files below `internal/ride/`, and `cmd/service/ride.go`; it also inserts wiring into `cmd/service/main.go`. It declares no dynamic parameters, so an extra parameter such as `--fields` is not valid for this generator. Always check `gen list` against your installed template version.

`--no-build` explicitly requests file-only generation, including file and anchor changes. It does not compile, format or run hooks. Without it, the default build request receives a typed unavailable error before any generation effect. Explicit `--format` or `--hooks` requests also refuse before effects. Templates with configured unsupported actions can still be refused with `--no-build`; the flag does not enable those actions or silently discard them.

## Generate a batch

A batch plans every operation before writing and uses one native transaction:

```sh
tplaiter gen batch \
  --project-context a --dir /absolute/canonical/projects/a \
  --operations '[{"kind":"entity","name":"Ride"},{"kind":"entity","name":"Driver"}]' \
  --no-build --json
```

Run this example on a project where neither entity has already been generated. Existing target files and repeated insertion markers are refused. A conflicting operation prevents the batch from beginning its writes. Input is limited to 256 operations and 1 MiB of operations JSON.

For generators that declare parameters, use `--<parameter> <value>` for a single operation or a string-valued `params` object in its batch entry. Required values, types and patterns are checked before writes. Command controls are reserved: `json`, `no-build`, `project-context`, `dir`, `help`, `format`, `hooks` and `operations` cannot be generator parameter names or batch `params` keys.

Successful `--json` output is a `tplaiter.dev/result/v1` envelope identifying the installed project and the created/edited paths. Generation success is reported after commit. It does not report that the files were formatted or built.

## Failures and recovery limits

| Reported problem | Next step |
| --- | --- |
| Installation or provisioning is missing | Use the installed binary and complete `trust provision` as described in the installation guide. |
| The project key or directory does not match | Inspect `trust contexts`, select an existing key and use its exact root. |
| A generator is unavailable, a parameter is invalid, or a target already exists | Check the installed generator and settings, correct the input, or choose a new name. Do not overwrite files to force a retry. |
| Build, formatter or hooks are unavailable | Use file-only `--no-build` without executable action flags, with a supported template. |
| Project state or generator resources have changed | Preserve the project and resolve the mismatch through a maintainer; do not rewrite sealed files or locks. |
| A transaction fails or recovery is required | Preserve the project and tplaiter home, and ask a maintainer to inspect the unresolved operation before another mutation. |

A failed apply or commit attempts rollback of the operation's owned changes. Conflicts can prevent complete restoration; files changed by someone else are preserved. Do not assume an error means that every change was undone, or that a reported commit uncertainty is safe to retry.

The native library provides an exact transaction reopen API for cold recovery, with commit or rollback after revalidation. **The CLI currently exposes no recovery or continuation command.** Do not use another workflow's continuation command for generation. The unfinished-transaction guard and recovery readiness remain separate pending work; the restored file-only commands do not imply that these protections are complete.
