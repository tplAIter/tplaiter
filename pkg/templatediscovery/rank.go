package templatediscovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func Digest(b []byte) string { v := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(v[:]) }
func (p SourcePin) Valid() bool {
	if len(p.Repo) > 128 || len(p.Path) > 1024 || !utf8.ValidString(p.Repo) || !utf8.ValidString(p.Path) || (p.Commit != "" && !commitRE.MatchString(p.Commit)) || (p.ManifestSHA256 != "" && !digestRE.MatchString(p.ManifestSHA256)) {
		return false
	}
	if p.Qualification == "owner-supplied" {
		return p.SourceID != "" && len(p.SourceID) <= 256 && p.Revision != "" && len(p.Revision) <= 256 && digestRE.MatchString(p.ContentSHA256) && utf8.ValidString(p.SourceID) && utf8.ValidString(p.Revision)
	}
	return p.Qualification == "local-observed" && p.SourceID == "" && p.Revision == "" && p.ContentSHA256 == "" && nameRE.MatchString(p.Repo) && p.Path != "" && !strings.ContainsAny(p.Path, "\\\x00\r\n:") && !path.IsAbs(p.Path) && path.Clean(p.Path) == p.Path && p.Path != ".." && !strings.HasPrefix(p.Path, "../") && commitRE.MatchString(p.Commit) && digestRE.MatchString(p.ManifestSHA256)
}
func Normalize(q Query) (Query, error) {
	if !utf8.ValidString(q.Task) || len(strings.TrimSpace(q.Task)) == 0 || len(q.Task) > 4096 || len(q.Language) > 128 || len(q.Framework) > 128 || len(q.Labels) > 16 {
		return q, ErrInput
	}
	if q.MaxCandidates == 0 {
		q.MaxCandidates = 64
	}
	if q.MaxResults == 0 {
		q.MaxResults = 5
	}
	if q.MaxBytes == 0 {
		q.MaxBytes = 16384
	}
	if q.MaxCandidates < 1 || q.MaxCandidates > 256 || q.MaxResults < 1 || q.MaxResults > 20 || q.MaxBytes < MinBytes || q.MaxBytes > 65536 {
		return q, ErrInput
	}
	for _, l := range q.Labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" || v == "" || len(l) > 256 {
			return q, ErrInput
		}
	}
	switch q.Facts.Status {
	case "":
		q.Facts.Status = "not-requested"
	case "not-requested", "empty", "observed", "unavailable":
	default:
		return q, ErrInput
	}
	if len(q.Facts.Language) > 128 || len(q.Facts.Template) > 256 || len(q.Facts.Frameworks) > 8 || len(q.Facts.Evidence) > 3 {
		return q, ErrInput
	}
	for _, f := range q.Facts.Frameworks {
		if len(f) > 128 {
			return q, ErrInput
		}
	}
	for _, e := range q.Facts.Evidence {
		if len(e.Path) > 128 || !digestRE.MatchString(e.SHA256) {
			return q, ErrInput
		}
	}
	if q.Facts.Frameworks == nil {
		q.Facts.Frameworks = []string{}
	}
	if q.Facts.Evidence == nil {
		q.Facts.Evidence = []FactEvidence{}
	}
	return q, nil
}

// Identify bounds normalized metadata (up to65 groups/64 values after the
// strictly bounded companion use-cases projection), canonicalizes collections, and derives
// an immutable content ID. It authenticates neither the pin nor its publisher.
func Identify(c Candidate) (Candidate, error) {
	if !c.SourcePin.Valid() || !digestRE.MatchString(c.MetadataSHA256) || !nameRE.MatchString(c.Name) || len(c.Version) > 128 || len(c.Description) > 4096 || !utf8.ValidString(c.Description) || !c.CandidateKind.Valid() || !c.Readiness.Valid() || len(c.Labels) > 65 || len(c.Blocks) > 32 || len(c.Skills) > 32 {
		return c, ErrInput
	}
	labels := map[string][]string{}
	for k, values := range c.Labels {
		if len(k) == 0 || len(k) > 128 || len(values) > 64 {
			return c, ErrInput
		}
		v := append([]string{}, values...)
		for _, x := range v {
			if len(x) > 256 || !utf8.ValidString(x) {
				return c, ErrInput
			}
		}
		sort.Strings(v)
		labels[k] = unique(v)
	}
	c.Labels = labels
	refs := func(v []Reference) ([]Reference, error) {
		out := append([]Reference{}, v...)
		for _, r := range out {
			if r.ID == "" || len(r.ID) > 128 || !utf8.ValidString(r.ID) || !r.SourcePin.Valid() || !r.CandidateKind.Valid() || !r.Readiness.Valid() || r.DeclarationStatus != "metadata-declared" || (r.Availability != "metadata-declared" && r.Availability != "admitted-record" && r.Availability != "unavailable") {
				return nil, ErrInput
			}

			if r.Availability == "admitted-record" {
				p := r.Provenance
				if p == nil || p.ExportID != r.ID || p.ContentSHA256 != r.SourcePin.ContentSHA256 || !digestRE.MatchString(p.CatalogSource) || !digestRE.MatchString(p.ContractSHA256) || !digestRE.MatchString(p.ContentSHA256) || p.Provider == "" || len(p.Provider) > 256 || !utf8.ValidString(p.Provider) || (p.Domain != "block" && p.Domain != "skill" && p.Domain != "approach") {
					return nil, ErrInput
				}
			} else if r.Provenance != nil {
				return nil, ErrInput
			}
		}
		sort.Slice(out, func(i, j int) bool {
			a, _ := json.Marshal(out[i])
			b, _ := json.Marshal(out[j])
			return string(a) < string(b)
		})
		return out, nil
	}
	var err error
	c.Blocks, err = refs(c.Blocks)
	if err != nil {
		return c, err
	}
	c.Skills, err = refs(c.Skills)
	if err != nil {
		return c, err
	}
	c.ID = ""
	raw, _ := json.Marshal(c)
	c.ID = Digest(append([]byte("tplaiter.dev/template-suggestion/v1\x00"), raw...))
	return c, nil
}
func unique(v []string) []string {
	out := []string{}
	for _, s := range v {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
func tokens(s string) []string {
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
	sort.Strings(parts)
	out := []string{}
	for _, p := range unique(parts) {
		if utf8.RuneCountInString(p) >= 2 {
			out = append(out, p)
		}
	}
	return out
}
func contains(values []string, needle string) bool {
	for _, v := range values {
		if strings.EqualFold(v, needle) {
			return true
		}
	}
	return false
}
func diagnostic(r *Result, code, id, field string) {
	if len(r.Diagnostics) < 32 {
		r.Diagnostics = append(r.Diagnostics, Diagnostic{code, id, field})
	} else {
		r.Budget.Truncated = true
	}
}

// Rank computes scores on a bounded input and orders by score/ID before
// applying the shortlist budget. No caller-provided next
// calls or prose commands are accepted. Public followups are constructed here.
func Rank(q Query, input []Candidate) (Result, error) {
	q, err := Normalize(q)
	if err != nil {
		return Result{}, err
	}
	r := Result{APIVersion: APIVersion, Qualification: "descriptive-data-only", Facts: q.Facts, Suggestions: []Suggestion{}, Diagnostics: []Diagnostic{}, Budget: Budget{MaxCandidates: q.MaxCandidates, MaxResults: q.MaxResults, MaxBytes: q.MaxBytes}}
	if len(input) > 4096 {
		return r, ErrInput
	}
	candidates := []Candidate{}
	r.Budget.Considered = len(input)
	// Validate bounds before any canonical sorting/serialization of caller data.
	for _, c := range input {
		v, e := Identify(c)
		if e != nil || !digestRE.MatchString(c.ID) || c.ID != v.ID {
			diagnostic(&r, "metadata_invalid", "", "candidate")
			continue
		}
		candidates = append(candidates, v)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	if q.Facts.Status == "unavailable" {
		diagnostic(&r, "project_unavailable", "", "project")
		return Fit(r, q.MaxBytes)
	}
	queryTokens := tokens(q.Task)
	if len(queryTokens) > 64 {
		queryTokens = queryTokens[:64]
		r.Budget.Truncated = true
		diagnostic(&r, "budget_exhausted", "", "tokens")
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		if c.Description == "" || len(c.Labels) == 0 {
			diagnostic(&r, "metadata_missing", c.ID, "description/labels")
		}
		tagsPresent := false
		for _, tag := range c.Labels["tags"] {
			if strings.TrimSpace(tag) != "" {
				tagsPresent = true
			}
		}
		if !tagsPresent {
			diagnostic(&r, "metadata_missing", c.ID, "labels.tags")
		}
		if c.Readiness == Unknown {
			diagnostic(&r, "metadata_missing", c.ID, "readiness")
		}
		lang := q.Language
		if lang == "" {
			lang = q.Facts.Language
		}
		compatible := true
		for _, constraint := range []struct{ k, v string }{{"lang", lang}, {"framework", q.Framework}} {
			if constraint.v == "" {
				continue
			}
			if len(c.Labels[constraint.k]) == 0 {
				diagnostic(&r, "constraint_unknown", c.ID, constraint.k)
				compatible = false
			} else if !contains(c.Labels[constraint.k], constraint.v) {
				compatible = false
			}
		}
		if q.Framework == "" && len(q.Facts.Frameworks) > 0 {
			match := false
			for _, f := range q.Facts.Frameworks {
				if contains(c.Labels["framework"], f) {
					match = true
				}
			}
			if !match {
				compatible = false
				if len(c.Labels["framework"]) == 0 {
					diagnostic(&r, "constraint_unknown", c.ID, "framework")
				}
			}
		}
		for _, l := range q.Labels {
			k, v, _ := strings.Cut(l, "=")
			if !contains(c.Labels[k], v) {
				compatible = false
			}
		}
		if !compatible {
			continue
		}
		s := Suggestion{ID: c.ID, MetadataSHA256: c.MetadataSHA256, SourcePin: c.SourcePin, Name: c.Name, Version: c.Version, CandidateKind: c.CandidateKind, Readiness: c.Readiness, Reasons: []MatchReason{}, Blocks: []Reference{}, Skills: []Reference{}, NextToolCalls: []ReadOnlyCall{}}
		s.Description, s.DescriptionTruncated = shortDescription(c.Description, 512)
		if s.DescriptionTruncated {
			r.Budget.Truncated = true
			diagnostic(&r, "metadata_truncated", c.ID, "description")
		}
		if !tagsPresent {
			s.Readiness = Unknown
		}
		fields := []struct {
			name, value string
			weight      int
		}{{"name", c.Name, 3}, {"description", c.Description, 1}}
		keys := []string{}
		for k := range c.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range c.Labels[k] {
				fields = append(fields, struct {
					name, value string
					weight      int
				}{"labels." + k, v, 4})
			}
		}
		for _, f := range fields {
			ts := tokens(f.value)
			for _, t := range queryTokens {
				if contains(ts, t) {
					s.Score += f.weight
					if len(s.Reasons) < 16 {
						s.Reasons = append(s.Reasons, MatchReason{f.name, t, f.value})
					}
				}
			}
		}
		if s.Score == 0 {
			continue
		}
		relevant := func(ref Reference) bool {
			for _, t := range queryTokens {
				if contains(tokens(ref.ID), t) {
					return true
				}
			}
			return false
		}
		selectReferences := func(refs []Reference) []Reference {
			selected := []Reference{}
			for _, ref := range refs {
				if relevant(ref) {
					selected = append(selected, ref)
				}
			}
			if len(selected) == 0 {
				// A declared candidate use-case already matched. IDs need not be
				// natural-language descriptions; retain actual admitted records as
				// bounded descriptive context, never promote unavailable declarations.
				for _, ref := range refs {
					if ref.Availability == "admitted-record" {
						selected = append(selected, ref)
					}
				}
			}
			if len(selected) > 2 {
				selected = selected[:2]
				r.Budget.Truncated = true
				diagnostic(&r, "budget_exhausted", c.ID, "references")
			}
			return selected
		}
		s.Blocks = selectReferences(c.Blocks)
		s.Skills = selectReferences(c.Skills)
		if c.SourcePin.Qualification == "local-observed" {
			s.NextToolCalls = append(s.NextToolCalls, ReadOnlyCall{Tool: "template_show", Arguments: map[string]any{"ref": c.SourcePin.Repo + "/" + c.Name, "commit": c.SourcePin.Commit, "manifestSHA256": c.SourcePin.ManifestSHA256}})
		}
		r.Suggestions = append(r.Suggestions, s)
	}
	sort.Slice(r.Suggestions, func(i, j int) bool {
		if r.Suggestions[i].Score != r.Suggestions[j].Score {
			return r.Suggestions[i].Score > r.Suggestions[j].Score
		}
		return r.Suggestions[i].ID < r.Suggestions[j].ID
	})
	if len(r.Suggestions) > q.MaxCandidates {
		r.Suggestions = r.Suggestions[:q.MaxCandidates]
		r.Budget.Truncated = true
		diagnostic(&r, "budget_exhausted", "", "candidates")
	}
	if len(r.Suggestions) > q.MaxResults {
		r.Suggestions = r.Suggestions[:q.MaxResults]
		r.Budget.Truncated = true
		diagnostic(&r, "budget_exhausted", "", "results")
	}
	if len(input) == 0 {
		diagnostic(&r, "empty_catalog", "", "catalog")
	} else if len(r.Suggestions) == 0 {
		diagnostic(&r, "no_match", "", "task")
	}
	return Fit(r, q.MaxBytes)
}

// Fit removes complete optional records, keeping the mandatory typed output
// floor. maxBytes includes serialized data, not its surrounding result envelope.
func Fit(r Result, maxBytes int) (Result, error) {
	if maxBytes < 512 {
		return r, ErrInput
	}
	r.Budget.MaxBytes = maxBytes
	for {
		r.Budget.Emitted = len(r.Suggestions)
		// Fixed point: adding the bytes count can change its own decimal width.
		for i := 0; i < 4; i++ {
			raw, _ := json.Marshal(r)
			if r.Budget.Bytes == len(raw) {
				break
			}
			r.Budget.Bytes = len(raw)
		}
		raw, _ := json.Marshal(r)
		if len(raw) <= maxBytes {
			return r, nil
		}
		r.Budget.Truncated = true
		if len(r.Suggestions) > 0 {
			if len(r.Suggestions) == 1 {
				s := &r.Suggestions[0]
				if len(s.Description) > 128 {
					s.Description, _ = shortDescription(s.Description, 128)
					s.DescriptionTruncated = true
					continue
				}

				// Preserve a representative matched record before dropping the
				// whole suggestion. The admitted owner rebuilds exact read calls
				// from retained IDs after any reference truncation.
				if len(s.Skills) > 1 {
					s.Skills = s.Skills[:len(s.Skills)-1]
					continue
				}
				if len(s.Blocks) > 1 {
					s.Blocks = s.Blocks[:len(s.Blocks)-1]
					continue
				}
				if len(s.Skills) > 0 && len(s.Blocks) > 0 {
					s.Skills = s.Skills[:0]
					continue
				}
				if len(s.NextToolCalls) > 1 {
					s.NextToolCalls = s.NextToolCalls[:len(s.NextToolCalls)-1]
					continue
				}
				if len(s.Reasons) > 0 {
					s.Reasons = s.Reasons[:len(s.Reasons)-1]
					continue
				}
				if len(s.Description) > 32 {
					s.Description, _ = shortDescription(s.Description, 32)
					s.DescriptionTruncated = true
					continue
				}

				// Optional receipt/detail records must not displace the final
				// useful grounded reference and its exact read call. Retain
				// observed status and constraints; report omitted records via
				// the mandatory truncation flag.
				if len(r.Diagnostics) > 0 {
					r.Diagnostics = r.Diagnostics[:len(r.Diagnostics)-1]
					continue
				}
				if len(r.Facts.Evidence) > 0 {
					r.Facts.Evidence = r.Facts.Evidence[:len(r.Facts.Evidence)-1]
					continue
				}
			}
			r.Suggestions = r.Suggestions[:len(r.Suggestions)-1]
			diagnostic(&r, "budget_exhausted", "", "bytes")
			continue
		}
		if len(r.Diagnostics) > 1 {
			r.Diagnostics = r.Diagnostics[:len(r.Diagnostics)-1]
			continue
		}
		r.Facts = ProjectFacts{Status: r.Facts.Status, Frameworks: []string{}, Evidence: []FactEvidence{}}
		if len(raw) > maxBytes && len(r.Diagnostics) == 1 && r.Diagnostics[0].Code != "budget_exhausted" {
			r.Diagnostics = []Diagnostic{{Code: "budget_exhausted", Field: "bytes"}}
			continue
		}
		raw, _ = json.Marshal(r)
		if len(raw) > maxBytes {
			return r, ErrInput
		}
	}
}

// shortDescription is a byte-bounded excerpt of the canonical authored text.
// It never invents a summary, and explicit truncation preserves source identity.
func shortDescription(value string, limit int) (string, bool) {
	if len(value) <= limit {
		return value, false
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value, true
}
