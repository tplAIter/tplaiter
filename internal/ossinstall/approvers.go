package ossinstall

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"os"
	"sort"
)

type ExecutionEvidence struct {
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"dataBase64"`
}
type executionOptionsKey struct{}

func executionOptions(ctx context.Context) Options {
	o, _ := ctx.Value(executionOptionsKey{}).(Options)
	return o
}
func executionContext(ctx context.Context, o Options) (context.Context, error) {
	if o.Approvers == nil && o.ExecutionEvidence == nil {
		return ctx, nil
	}
	if o.Rotate || o.SourcePackages == nil || o.ProjectContexts == nil {
		return nil, errors.New("ossinstall: execution inputs require fresh signed-source registration and explicit projects")
	}
	if _, e := os.Lstat(o.Root); !os.IsNotExist(e) {
		return nil, ErrEnrollmentChanged
	}
	var total int

	for _, v := range o.ExecutionEvidence {
		b, e := base64.StdEncoding.Strict().DecodeString(v.DataBase64)
		if e != nil || len(b) > 4<<20 || evidencecas.Digest(b) != v.SHA256 {
			return nil, errors.New("ossinstall: invalid execution evidence")
		}
		total += len(b)
		if total > 512<<20 {
			return nil, errors.New("ossinstall: execution evidence limit")
		}
	}
	if len(o.ExecutionEvidence) > 20000 {
		return nil, errors.New("ossinstall: execution evidence count")
	}
	return context.WithValue(ctx, executionOptionsKey{}, o), nil
}
func (g *generator) applyExecutionInputs(p *trustverify.ExecutionPolicy) error {
	o := executionOptions(g.context())
	for _, a := range o.Approvers {
		p.Approvers = append(p.Approvers, a)
		exists := false
		for _, v := range p.Principals {
			if v.ID == a.PrincipalID {
				exists = true
			}
		}
		if !exists {
			p.Principals = append(p.Principals, trustverify.Principal{ID: a.PrincipalID})
		}
	}
	sort.Slice(p.Principals, func(i, j int) bool { return p.Principals[i].ID < p.Principals[j].ID })
	for _, v := range o.ExecutionEvidence {
		b, e := base64.StdEncoding.Strict().DecodeString(v.DataBase64)
		if e != nil || evidencecas.Digest(b) != v.SHA256 {
			return errors.New("ossinstall: invalid execution evidence")
		}
		g.put(b)
	}
	return nil
}
