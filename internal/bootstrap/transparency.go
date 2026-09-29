package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

type TransparencyEvidence struct {
	CheckpointCAS       string
	InclusionProofCAS   string
	ConsistencyProofCAS string
}

func verifyTransparency(ctx context.Context, store evidencecas.Reader, id, leaf string, r Receipt, refs TransparencyEvidence) (Checkpoint, error) {
	if store == nil || refs.CheckpointCAS != r.CheckpointDigest || !validDigest(refs.InclusionProofCAS) {
		return Checkpoint{}, errors.New("bootstrap: transparency evidence is not receipt-bound")
	}
	raw, e := readEvidence(ctx, store, refs.CheckpointCAS)
	if e != nil {
		return Checkpoint{}, fmt.Errorf("bootstrap: load checkpoint: %w", e)
	}
	c, e := DecodeCheckpoint(raw)
	if e != nil {
		return Checkpoint{}, e
	}
	if c.APIVersion != CheckpointAPIVersion || c.AuthorityID != id || c.TreeSize != r.TreeSize || !validDigest(c.RootHash) {
		return Checkpoint{}, errors.New("bootstrap: checkpoint mismatch")
	}
	raw, e = readEvidence(ctx, store, refs.InclusionProofCAS)
	if e != nil {
		return Checkpoint{}, e
	}
	p, e := DecodeInclusionProof(raw)
	if e != nil {
		return Checkpoint{}, e
	}
	if p.APIVersion != InclusionAPIVersion || p.TreeSize != c.TreeSize || p.Hashes == nil {
		return Checkpoint{}, errors.New("bootstrap: inclusion proof metadata mismatch")
	}
	hashes := make([]MerkleHash, len(p.Hashes))
	for i, x := range p.Hashes {
		if hashes[i], e = merkleHash(x); e != nil {
			return Checkpoint{}, e
		}
	}
	root, e := merkleHash(c.RootHash)
	if e != nil {
		return Checkpoint{}, e
	}
	if e = VerifyInclusion([]byte(leaf), p.LeafIndex, p.TreeSize, root, hashes); e != nil {
		return Checkpoint{}, e
	}
	return *c, nil
}
