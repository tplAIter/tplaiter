# Native signed readonly diff

The published `f72ad96` slice adds a bounded readonly diff for an authenticated
installed native project. It compares the current project with the independently
reconstructed signed source baseline and reports observations only. It does not
create, adopt, link, update, rebaseline, reanswer, or execute anything.

## CLI

Use an installed, provisioned binary and an authenticated finite project context:

```sh
tplaiter diff --project-context KEY --dir ROOT --json --exit-code
```

`--project-context` selects the installed context key. `--dir` is an explicit
locator for the authenticated project root and must resolve to that context's
root; changing the process working directory does not select another project.
The signed source and baseline are reconstructed from the installed context's
closed lock pair and authenticated evidence. A caller-selected checkout,
manifest, or current directory cannot replace them. `--offline=false` is
refused. `--json` emits the normal result envelope. A successful observation
returns exit 0; `--exit-code` returns the finding exit when changes exist.
Typed authentication, malformed-state, stale-observation, cancellation, and
unsupported-scope failures retain their typed refusal and do not expose a
partial verified project payload.

Rows are independent observations. A file row uses `path`; a managed block row
uses `(path, blockId)` and is rendered as `path#blockId` in text output. A change
to two managed blocks therefore produces two block rows and no synthetic
whole-file row. Skeleton or mode drift is reported as a distinct `skeleton` row.
File and block summary counts are disjoint.

## MCP

The `project_diff` tool accepts only these controls:

```json
{
  "dir": "ROOT",
  "projectContext": "KEY",
  "exitCode": true
}
```

The server forwards the resolved directory as both the explicit CLI root
locator and child working directory. Unknown or malformed controls, including
execution, source, approval, trust, or update controls, refuse before child
launch. The operation uses the existing held-child transport and has no runner,
shell, import, refresh, hook, or module-execution dependency. It is read-only:
the diff session performs authenticated reads and re-observations and creates no
project, baseline, block, ownership, receipt, or recovery state.

The implementation is bounded by the existing native source/render limits,
4096 files, 64 MiB total current content, 16 MiB per current file, 4096 block
and change rows, 8192 marker tokens per parsed image, and 1024-byte paths.
Missing, malformed, stale, conflicting, or unsupported signed evidence refuses
with a typed result rather than being treated as an empty diff.

## Qualification and remaining scope

The installed CLI/MCP proof uses a synthetic signed fixture and explicitly
materializes a literal managed-block baseline. It proves the actual readonly
diff process, including file rows, independent block rows, skeleton/mode
classification, and zero-write snapshots; it does not prove managed-project
creation or adoption. It does not complete parent P06, linking, adoption,
reanswer, extra Gen-owned inventory composition, or generic Inspector
readiness. No all-model or overall-readiness claim follows from this slice.

The separate [native approved project build](adr/native-approved-project-build.md)
remains bounded to a dependency-free Darwin arm64 literal Go build with an
approved closed toolchain, persistent signed approval import, and a real
process receipt. Its unsigned, stale-binding, and cancellation refusals remain
typed; default generation builds and dependency-bearing or Temporal builds are
still outside the approved scope.


## Connected managed Update lineage

The [managed root-Go lifecycle](native-managed-decisions.md) separately derives
New/Link clean lineage and committed native Update lineage from actual
source/effect owner records. Diff reconstructs that owner intent and verifies
the complete recorded ledger. A KEEP block absent from the signed target may be
inspected only through its authenticated upstream tombstone. Unknown block IDs
or providers still refuse; an unverified baseline never licenses new topology.
The clean formatted target remains the upstream comparison baseline, separate
from retained local content. This connected reader does not alter the historical
initial Diff fixture's qualification or grant recovery, execution or writing.
