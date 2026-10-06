// Package execx — mockable layer for launching external processes.
//
// tplaiter constantly orchestrates external tools (git, glab, gh, brew, ansible,
// arbitrary manifest shell commands). All this code must use [Runner], rather
// than os/exec directly, so tests can substitute [RecordingRunner] without
// touching the real environment.
package execx

import "github.com/tplAIter/tplaiter/internal/execcontract"

// Result, Options and Runner preserve the shared process interface types.
type Result = execcontract.Result
type Options = execcontract.Options
type Runner = execcontract.Runner
