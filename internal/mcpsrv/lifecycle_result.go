package mcpsrv

import "github.com/tplAIter/tplaiter/internal/resultdto"

// EncodeLifecycleResult emits the same canonical result/v1 JSON the CLI
// prints with --json, keeping MCP structured payloads byte-identical to CLI
// output.
func EncodeLifecycleResult(result resultdto.Result) ([]byte, error) {
	return resultdto.MarshalCanonical(result)
}

// DecodeLifecycleResult validates a CLI result at the MCP boundary while
// retaining unknown additive fields and rejecting unknown major versions.
func DecodeLifecycleResult(data []byte) (resultdto.Result, error) {
	return resultdto.Decode(data)
}

// ValidateLifecycleResult checks every result/v1 rule, including the
// operation registry and project scope.
func ValidateLifecycleResult(result resultdto.Result) error {
	return result.Validate()
}

// LifecycleExitCode classifies an error by its typed members only.
func LifecycleExitCode(err error) resultdto.ExitCode {
	return resultdto.Classify(err)
}
