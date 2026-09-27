package cmd

import (
	"errors"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// trustExecutionUnavailable keeps stock command composition closed until a
// lifecycle owner supplies the separately approved fixed C/T3 action.
func trustExecutionUnavailable() error {
	return errors.Join(trustload.ErrProvenanceUnavailable, errors.New("TRUST_EXECUTION_UNAVAILABLE"))
}
