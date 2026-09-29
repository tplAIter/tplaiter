package resultdto

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	blockIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)
	sha256Pattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// Validate checks every result/v1 rule that the JSON schema also expresses,
// plus the registry rules (operation/kind pairing and project scope).
func (r *Result) Validate() error {
	if r == nil {
		return errors.New("result is nil")
	}
	if r.APIVersion != APIVersion {
		return fmt.Errorf("unsupported result apiVersion %q", r.APIVersion)
	}
	if r.Meta.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported result schemaVersion %d", r.Meta.SchemaVersion)
	}
	if r.Kind == "" || r.Operation == "" || r.Status == "" {
		return errors.New("kind, operation and status are required")
	}
	if !utf8.ValidString(r.Kind) || !utf8.ValidString(string(r.Operation)) {
		return errors.New("kind and operation must be valid UTF-8")
	}
	if !validOperation(r.Operation) {
		return fmt.Errorf("unsupported result operation %q", r.Operation)
	}
	if err := ValidateOperationKind(r.Operation, r.Kind); err != nil {
		return err
	}
	if !validStatus(r.Status) {
		return fmt.Errorf("unsupported result status %q", r.Status)
	}
	if err := r.validateProject(); err != nil {
		return err
	}
	if r.TransactionID != nil && (*r.TransactionID == "" || !utf8.ValidString(*r.TransactionID)) {
		return errors.New("transactionId must be a non-empty valid UTF-8 string when present")
	}
	if r.Summary.FilesChanged < 0 || r.Summary.BlocksChanged < 0 || r.Summary.Conflicts < 0 {
		return errors.New("summary counters must be non-negative")
	}
	if r.Meta.TplaiterVersion == "" || !utf8.ValidString(r.Meta.TplaiterVersion) {
		return errors.New("meta.tplaiterVersion is required and must be valid UTF-8")
	}
	if r.Changes == nil || r.Diagnostics == nil || r.Artifacts == nil {
		return errors.New("changes, diagnostics and artifacts must be non-null arrays")
	}
	for _, c := range r.Changes {
		if err := relativePath(c.Path); err != nil {
			return fmt.Errorf("change path: %w", err)
		}
		if c.Action == "" || !utf8.ValidString(c.Action) {
			return errors.New("change action is required and must be valid UTF-8")
		}
		if c.BlockID != "" && !blockIDPattern.MatchString(c.BlockID) {
			return fmt.Errorf("change blockId is invalid: %q", c.BlockID)
		}
	}
	for _, d := range r.Diagnostics {
		if err := validateDiagnostic(d); err != nil {
			return err
		}
	}
	for _, a := range r.Artifacts {
		if a.Name == "" || !utf8.ValidString(a.Name) {
			return errors.New("artifact name is required and must be valid UTF-8")
		}
		if err := relativePath(a.Path); err != nil {
			return fmt.Errorf("artifact path: %w", err)
		}
		if !sha256Pattern.MatchString(a.SHA256) {
			return fmt.Errorf("artifact sha256 must be a lowercase sha256 digest: %q", a.SHA256)
		}
	}
	if r.PlanSHA256 != "" && !sha256Pattern.MatchString(r.PlanSHA256) {
		return fmt.Errorf("planSha256 must be a lowercase sha256 digest: %q", r.PlanSHA256)
	}
	if len(r.Data) > 0 {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(r.Data, &object); err != nil || object == nil {
			return errors.New("data must be a JSON object when present")
		}
	}
	return nil
}

// validateProject applies the registry scope: global operations never carry
// a project, project operations must identify one on success, and a present
// project is always well-formed.
func (r *Result) validateProject() error {
	scope, err := ScopeForOperation(r.Operation)
	if err != nil {
		return err
	}
	if r.Project == nil {
		if scope == ScopeProject && successStatus(r.Status) {
			return fmt.Errorf("operation %q requires a project on status %q", r.Operation, r.Status)
		}
		return nil
	}
	if scope == ScopeGlobal {
		return fmt.Errorf("operation %q is global and must not carry a project", r.Operation)
	}
	if r.Project.ID == "" || !utf8.ValidString(r.Project.ID) {
		return errors.New("project.id is required and must be valid UTF-8")
	}
	if r.Project.Root == "" || !isAbsolute(r.Project.Root) || !utf8.ValidString(r.Project.Root) {
		return fmt.Errorf("project.root must be absolute: %q", r.Project.Root)
	}
	return nil
}

func successStatus(s Status) bool {
	return s == StatusOK || s == StatusChanges || s == StatusConflicted
}

func validateDiagnostic(d Diagnostic) error {
	if d.Code == "" || d.Message == "" || !utf8.ValidString(d.Code) || !utf8.ValidString(d.Message) {
		return errors.New("diagnostic code and message are required and must be valid UTF-8")
	}
	if !validSeverity(d.Severity) {
		return fmt.Errorf("unsupported diagnostic severity %q", d.Severity)
	}
	if d.Details == nil {
		return errors.New("diagnostic details must be non-null")
	}
	if _, err := json.Marshal(d.Details); err != nil {
		return fmt.Errorf("diagnostic details must contain JSON values: %w", err)
	}
	if d.Path != "" {
		if err := relativePath(d.Path); err != nil {
			return fmt.Errorf("diagnostic path: %w", err)
		}
	}
	if d.BlockID != "" && !blockIDPattern.MatchString(d.BlockID) {
		return fmt.Errorf("diagnostic blockId is invalid: %q", d.BlockID)
	}
	return nil
}

func validSeverity(severity string) bool {
	switch severity {
	case "error", "warning", "info":
		return true
	}
	return false
}

func validStatus(s Status) bool {
	switch s {
	case StatusOK, StatusChanges, StatusConflicted, StatusBlocked, StatusFailed, StatusNotApplicable:
		return true
	}
	return false
}

func isAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\\\") ||
		(len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '/' || p[2] == '\\'))
}

func relativePath(p string) error {
	if p == "" {
		return errors.New("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("path contains NUL")
	}
	if isAbsolute(p) || strings.Contains(p, "\\") {
		return fmt.Errorf("path must be project-relative with slash separators: %q", p)
	}
	clean := path.Clean(p)
	if clean != p || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path escapes project root: %q", p)
	}
	return nil
}
