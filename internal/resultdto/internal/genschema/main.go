// Command genschema writes schema/result.v1.schema.json from the resultdto
// operation registry. Run it from the repository root:
//
//	go run ./internal/resultdto/internal/genschema > schema/result.v1.schema.json
//
// TestSchemaMatchesRegistry fails when the committed schema drifts.
package main

import (
	"fmt"
	"os"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func main() {
	raw, err := resultdto.GenerateSchema()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(raw)
}
