// Package sourcepackage captures public immutable Git bytes offline. Capture
// computes identity; it does not authenticate a publisher or mint a capability.
package sourcepackage

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type CaptureInput struct {
	RepositoryPath string `json:"repositoryPath"`
	Origin         string `json:"origin"`
	TemplatePath   string `json:"templatePath"`
	Commit         string `json:"commit"`
}

type CapturedSource struct {
	Subject trustverify.Subject
	Objects map[string][]byte
}

func (i CaptureInput) Validate() error {
	if !filepath.IsAbs(i.RepositoryPath) || filepath.Clean(i.RepositoryPath) != i.RepositoryPath || len(i.RepositoryPath) > 4096 || i.Origin == "" || len(i.Origin) > 4096 || strings.ContainsAny(i.Origin, "\x00\r\n") {
		return errors.New("sourcepackage: invalid local source identity")
	}
	if len(i.Commit) != 40 || strings.ToLower(i.Commit) != i.Commit {
		return errors.New("sourcepackage: full lowercase SHA-1 commit required")
	}
	if _, err := hex.DecodeString(i.Commit); err != nil {
		return errors.New("sourcepackage: invalid commit")
	}
	p := i.TemplatePath
	if len(p) == 0 || len(p) > 4096 || (p != "." && (strings.HasPrefix(p, "/") || strings.Contains(p, "\\"))) {
		return errors.New("sourcepackage: invalid template path")
	}
	if p != "." {
		for _, part := range strings.Split(p, "/") {
			if part == "" || part == "." || part == ".." {
				return errors.New("sourcepackage: invalid template path")
			}
			for _, r := range part {
				if r < 32 || r == 127 {
					return errors.New("sourcepackage: invalid template path")
				}
			}
		}
	}
	return nil
}

func Capture(ctx context.Context, input CaptureInput) (CapturedSource, error) {
	if ctx == nil {
		return CapturedSource{}, errors.New("sourcepackage: nil context")
	}
	if err := ctx.Err(); err != nil {
		return CapturedSource{}, err
	}
	if err := input.Validate(); err != nil {
		return CapturedSource{}, err
	}
	scratch, cleanup, err := snapshotRepository(ctx, input.RepositoryPath)
	if err != nil {
		return CapturedSource{}, err
	}
	defer cleanup()
	reader, err := newBatchReader(ctx, scratch, input.Origin)
	if err != nil {
		return CapturedSource{}, err
	}
	defer reader.close()
	snapshot, err := trustverify.CaptureSource(ctx, reader, trustverify.SourceIdentity{Origin: input.Origin, TemplatePath: input.TemplatePath, Commit: input.Commit}, trustverify.DefaultSourceLimits())
	if err != nil {
		return CapturedSource{}, err
	}
	if err := ctx.Err(); err != nil {
		return CapturedSource{}, err
	}
	return CapturedSource{Subject: snapshot.Subject(), Objects: reader.objects}, nil
}
