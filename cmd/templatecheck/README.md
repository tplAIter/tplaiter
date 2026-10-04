# Template checker generator preflight

Run the author-facing checker with an empty, runner-owned output directory:

```sh
go run ./cmd/templatecheck --template /path/to/template --output /path/to/empty-output --generator-preflight --json
```

The optional flag checks each available manifest generator using default
parameters. Missing required defaults fail explicitly. Unavailable generators
are reported as skipped for that settings combination.

It calls the actual core gen.Generate preparation for CheckFirst and
check-second, then gen.GenerateBatch to check shared target/anchor state.
A repeat and its normalized spelling must be rejected as a duplicate.
Manifest paths are confined before preparation. Each owned anchor must occur
exactly once; each insertion must consume and preserve exactly one unchanged
`gen.Context.Marker` and must not duplicate the anchor. These checks run before
Generate, independently of target-collision checks. The rendered fixtures remain
unchanged; no generator output is installed, and no template hook, formatter,
command, or build gate runs.

Success means preparation reached the current execution-unavailable gate.
It does not claim live CLI generation, generated code compilation, or P10
completion. Generated-language checks remain the caller's responsibility.

The composite action exposes the opt-in generator-preflight input, defaulting
to false. Consumers must pin the reviewed published action commit before
setting this input to true.
