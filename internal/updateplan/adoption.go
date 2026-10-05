package updateplan

import (
	"context"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/adoption"
)

func protectedNames(p *adoptionpolicy.Policy) []string {
	set := map[string]bool{".": true}
	for _, rel := range p.Paths() {
		for {
			set[rel] = true
			if rel == "." {
				break
			}
			rel = path.Dir(rel)
		}
	}
	out := make([]string, 0, len(set))
	for rel := range set {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}
func (b *Backend) protection(ctx context.Context, p *adoptionpolicy.Policy, o *observation, cold *adoptionpolicy.Protection) (*adoptionpolicy.Protection, error) {
	if p == nil {
		if cold != nil {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	proof, err := adoption.Read(ctx, b.runtime, b.home, p)
	if err != nil {
		return nil, err
	}
	frame := &adoptionpolicy.Protection{DecisionSHA256: p.DecisionSHA256, ReceiptID: proof.ReceiptID(), PlanSHA256: proof.PlanDigest(), ReceiptSHA256: proof.ReceiptDigest(), Paths: []adoptionpolicy.ProtectedPath{}}
	names := protectedNames(p)
	if cold != nil && (len(cold.Paths) != len(names) || cold.DecisionSHA256 != frame.DecisionSHA256 || cold.ReceiptID != frame.ReceiptID || cold.PlanSHA256 != frame.PlanSHA256 || cold.ReceiptSHA256 != frame.ReceiptSHA256) {
		return nil, ErrInvalid
	}
	for i, rel := range names {
		v := adoptionpolicy.Observation{SHA256: evidencecas.Digest(nil)}
		for _, image := range o.images {
			if image.Path == rel {
				v.Exists = true
				v.Directory = image.Kind == "directory"
				v.Mode = image.Mode
				v.SHA256 = evidencecas.Digest(o.files[rel])
				if info := o.identities[rel]; info != nil {
					v.Mode = uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
					v.Device, v.Inode = updateFileID(info)
				}
			}
		}
		if cold != nil {
			c := cold.Paths[i]
			if c.Path != rel || c.Observation.Exists != v.Exists || c.Observation.Directory != v.Directory || c.Observation.Mode&0o777 != v.Mode || c.Observation.SHA256 != v.SHA256 {
				return nil, ErrInvalid
			}
			v = c.Observation
		}
		if v.Exists && (v.Inode == 0 || !v.Directory && v.Mode > 0o777) || !v.Exists && (v.Inode != 0 || v.Mode != 0 || v.Device != 0) {
			return nil, ErrUnsafe
		}
		frame.Paths = append(frame.Paths, adoptionpolicy.ProtectedPath{Path: rel, Observation: v})
	}
	return frame, nil
}
func protectsMutation(p *adoptionpolicy.Policy, rel string) bool {
	for _, e := range p.Paths() {
		a, z := strings.ToLower(rel), strings.ToLower(e)
		if a == z || strings.HasPrefix(a, z+"/") || strings.HasPrefix(z, a+"/") {
			return true
		}
	}
	return false
}
