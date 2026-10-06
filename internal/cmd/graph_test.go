package cmd

import (
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"testing"
)

func TestGraphLeavesAndDependencyAlias(t *testing.T) {
	c := newGraphCmd()
	if len(c.Commands()) != 4 {
		t.Fatal("missing graph leaves")
	}
	for _, leaf := range c.Commands() {
		if resultOperation(leaf) != graphcmd.Operation(leaf.Name()) || classifyPrerun(leaf, nil) != prerunTrustOwned {
			t.Fatal("incorrect route classification")
		}
	}
	alias := newGraphLeaf("source", "graph")
	if resultOperation(alias) != graphcmd.Operation("source") {
		t.Fatal("different deps graph operation")
	}
}
