// Package envcontract validates the inert, signed metadata used to describe a
// native environment action and its pinned runtime. It has no process, file,
// network, approval, or installation authority.
package envcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/exports"
)

const (
	ActionsAPIVersion = "tplaiter.dev/environment-actions/v1"
	RuntimeAPIVersion = "tplaiter.dev/environment-runtime/v1"
	ExecutionProfile  = "approved-host-ansible/v1"
	HostEffects       = "host-user-process"

	MaxActionsBytes      = 64 << 10
	MaxPlaybooks         = 32
	MaxSourceFiles       = 256
	MaxSourceFileBytes   = 1 << 20
	MaxSourceTotalBytes  = 16 << 20
	MaxRuntimeFiles      = 2048
	MaxRuntimeFileBytes  = 64 << 20
	MaxRuntimeTotalBytes = 512 << 20
	MaxRuntimeIndexBytes = 1 << 20
	MaxCASChunkBytes     = 4 << 20
	MaxDigestBytes       = 72
	MaxNameBytes         = 256
	MaxArgvItems         = 128
	MaxArgvItemBytes     = 16 << 10
	MaxArgvTotalBytes    = 64 << 10
)

type ManifestPlaybook struct{ Name, File string }

type SnapshotFile struct {
	Path, Mode, SHA256 string
	Bytes              []byte
}

type SourceSnapshot struct {
	ManifestPath, ManifestSHA256 string
	Files                        []SnapshotFile
}

type FilePin struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

type Action struct {
	Name               string    `json:"name"`
	PlaybookFile       string    `json:"playbookFile"`
	Files              []FilePin `json:"files"`
	RuntimeIndexPath   string    `json:"runtimeIndexPath"`
	RuntimeIndexSHA256 string    `json:"runtimeIndexSHA256"`
	Argv               []string  `json:"argv"`
	TimeoutMillis      int64     `json:"timeoutMillis"`
	ExecutionProfile   string    `json:"executionProfile"`
	Effects            string    `json:"effects"`
	InventoryPath      string    `json:"inventoryPath"`
	ConfigPath         string    `json:"configPath"`
}

type ActionsDocument struct {
	APIVersion string   `json:"apiVersion"`
	Actions    []Action `json:"actions"`
}

type ChunkPin struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type RuntimeFile struct {
	Path       string     `json:"path"`
	Mode       string     `json:"mode"`
	SHA256     string     `json:"sha256"`
	Bytes      int64      `json:"bytes"`
	ChunkCount int        `json:"chunkCount"`
	Chunks     []ChunkPin `json:"chunks"`
}

type RuntimeDocument struct {
	APIVersion string        `json:"apiVersion"`
	GOOS       string        `json:"goos"`
	GOARCH     string        `json:"goarch"`
	ToolID     string        `json:"toolID"`
	Version    string        `json:"version"`
	Driver     FilePin       `json:"driver"`
	Files      []RuntimeFile `json:"files"`
	TotalBytes int64         `json:"totalBytes"`
}

func DecodeActions(raw []byte, manifest []ManifestPlaybook, snapshot SourceSnapshot) (ActionsDocument, error) {
	var doc ActionsDocument
	if err := decodeClosed(raw, MaxActionsBytes, []string{"apiVersion", "actions"}, &doc); err != nil {
		return doc, err
	}
	if doc.APIVersion != ActionsAPIVersion {
		return doc, errors.New("envcontract: unsupported actions apiVersion")
	}
	if err := validateSourceSnapshot(snapshot); err != nil {
		return doc, err
	}
	if len(doc.Actions) > MaxPlaybooks || len(doc.Actions) != len(manifest) {
		return doc, errors.New("envcontract: action count does not match manifest")
	}
	manifestByName := make(map[string]ManifestPlaybook, len(manifest))
	for i, p := range manifest {
		if err := validateName(p.Name); err != nil {
			return doc, fmt.Errorf("envcontract: manifest playbook %d: %w", i, err)
		}
		if err := validatePath(p.File); err != nil {
			return doc, fmt.Errorf("envcontract: manifest playbook %d: %w", i, err)
		}
		if _, ok := manifestByName[p.Name]; ok {
			return doc, errors.New("envcontract: duplicate manifest playbook")
		}
		manifestByName[p.Name] = p
	}
	if !sort.SliceIsSorted(doc.Actions, func(i, j int) bool { return doc.Actions[i].Name < doc.Actions[j].Name }) {
		return doc, errors.New("envcontract: actions are not sorted")
	}
	seen := map[string]bool{}
	union := map[string]FilePin{}
	for i := range doc.Actions {
		a := &doc.Actions[i]
		if err := validateAction(a); err != nil {
			return doc, fmt.Errorf("envcontract: action %d: %w", i, err)
		}
		p, ok := manifestByName[a.Name]
		if !ok || p.File != a.PlaybookFile {
			return doc, fmt.Errorf("envcontract: action %q does not map to manifest", a.Name)
		}
		if seen[a.Name] {
			return doc, errors.New("envcontract: duplicate action name")
		}
		seen[a.Name] = true
		perAction := make(map[string]FilePin, len(a.Files))
		paths := make([]string, 0, len(a.Files))
		for _, f := range a.Files {
			if err := validateFilePin(f); err != nil {
				return doc, err
			}
			if f.Mode != "100644" {
				return doc, fmt.Errorf("envcontract: source closure path %q is not 100644", f.Path)
			}
			if _, exists := perAction[f.Path]; exists {
				return doc, fmt.Errorf("envcontract: duplicate closure path %q", f.Path)
			}
			perAction[f.Path] = f
			paths = append(paths, f.Path)
			actual, ok := snapshotFile(snapshot.Files, f.Path)
			if !ok {
				return doc, fmt.Errorf("envcontract: closure path %q missing from snapshot", f.Path)
			}
			if actual.Mode != f.Mode || actual.SHA256 != f.SHA256 {
				return doc, fmt.Errorf("envcontract: closure pin mismatch for %q", f.Path)
			}
			if previous, exists := union[f.Path]; exists && previous != f {
				return doc, fmt.Errorf("envcontract: shared closure pin mismatch for %q", f.Path)
			}
			union[f.Path] = f
		}
		if err := validatePathSet(paths); err != nil {
			return doc, err
		}
		required := []FilePin{
			{Path: a.PlaybookFile, Mode: "100644", SHA256: ""},
			{Path: a.InventoryPath, Mode: "100644", SHA256: ""},
			{Path: a.ConfigPath, Mode: "100644", SHA256: ""},
			{Path: a.RuntimeIndexPath, Mode: "100644", SHA256: a.RuntimeIndexSHA256},
		}
		for _, want := range required {
			got, ok := perAction[want.Path]
			if !ok || got.Mode != want.Mode || (want.SHA256 != "" && got.SHA256 != want.SHA256) {
				return doc, fmt.Errorf("envcontract: required action input %q absent or mismatched", want.Path)
			}
		}
	}
	closure := make(map[string]bool, len(union))
	for path := range union {
		closure[path] = true
	}
	for _, f := range snapshot.Files {
		if f.Path != snapshot.ManifestPath && !closure[f.Path] {
			return doc, fmt.Errorf("envcontract: snapshot file %q is outside closure", f.Path)
		}
	}
	return doc, nil
}

func DecodeRuntime(raw []byte) (RuntimeDocument, error) {
	var doc RuntimeDocument
	if err := decodeClosed(raw, MaxRuntimeIndexBytes, []string{"apiVersion", "goos", "goarch", "toolID", "version", "driver", "files", "totalBytes"}, &doc); err != nil {
		return doc, err
	}
	if doc.APIVersion != RuntimeAPIVersion || !validPlatform(doc.GOOS, doc.GOARCH) || validateToken(doc.ToolID, MaxNameBytes) != nil || validateToken(doc.Version, MaxNameBytes) != nil {
		return doc, errors.New("envcontract: invalid runtime identity")
	}
	if len(doc.Files) == 0 || len(doc.Files) > MaxRuntimeFiles || doc.TotalBytes < 0 || doc.TotalBytes > MaxRuntimeTotalBytes {
		return doc, errors.New("envcontract: invalid runtime bounds")
	}
	if err := validateFilePin(doc.Driver); err != nil {
		return doc, fmt.Errorf("envcontract: driver: %w", err)
	}
	if doc.Driver.Mode != "100755" {
		return doc, errors.New("envcontract: driver must be 100755")
	}
	if !sort.SliceIsSorted(doc.Files, func(i, j int) bool { return doc.Files[i].Path < doc.Files[j].Path }) {
		return doc, errors.New("envcontract: runtime files are not sorted")
	}
	seen := map[string]bool{}
	paths := make([]string, 0, len(doc.Files))
	total := int64(0)
	driverFound := false
	for i := range doc.Files {
		f := &doc.Files[i]
		if err := validateFilePin(FilePin{Path: f.Path, Mode: f.Mode, SHA256: f.SHA256}); err != nil {
			return doc, err
		}
		if seen[f.Path] {
			return doc, fmt.Errorf("envcontract: duplicate runtime path %q", f.Path)
		}
		seen[f.Path] = true
		paths = append(paths, f.Path)
		if f.Mode != "100644" && f.Mode != "100755" {
			return doc, fmt.Errorf("envcontract: invalid runtime mode %q", f.Mode)
		}
		if f.Bytes < 0 || f.Bytes > MaxRuntimeFileBytes || f.ChunkCount != len(f.Chunks) || f.ChunkCount == 0 {
			return doc, fmt.Errorf("envcontract: invalid runtime file %q", f.Path)
		}
		chunkTotal := int64(0)
		for _, c := range f.Chunks {
			if !validDigest(c.SHA256) || c.Bytes < 1 || c.Bytes > MaxCASChunkBytes {
				return doc, fmt.Errorf("envcontract: invalid chunks for %q", f.Path)
			}
			chunkTotal += c.Bytes
		}
		if chunkTotal != f.Bytes {
			return doc, fmt.Errorf("envcontract: chunk total mismatch for %q", f.Path)
		}
		total += f.Bytes
		if f.Path == doc.Driver.Path {
			if f.SHA256 != doc.Driver.SHA256 || f.Mode != doc.Driver.Mode {
				return doc, errors.New("envcontract: driver pin mismatch")
			}
			driverFound = true
		}
	}
	if err := validatePathSet(paths); err != nil {
		return doc, err
	}
	if !driverFound || total != doc.TotalBytes {
		return doc, errors.New("envcontract: driver or total mismatch")
	}
	return doc, nil
}

func CanonicalActions(v ActionsDocument) ([]byte, error) { return canonicaljson.Canonical(v) }
func CanonicalRuntime(v RuntimeDocument) ([]byte, error) { return canonicaljson.Canonical(v) }
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ActionsDigest(v ActionsDocument) (string, error) {
	b, e := CanonicalActions(v)
	return Digest(b), e
}
func RuntimeDigest(v RuntimeDocument) (string, error) {
	b, e := CanonicalRuntime(v)
	return Digest(b), e
}

func CloneActions(v ActionsDocument) ActionsDocument {
	out := v
	if v.Actions != nil {
		out.Actions = make([]Action, len(v.Actions))
		copy(out.Actions, v.Actions)
	}
	for i := range out.Actions {
		if v.Actions[i].Argv != nil {
			out.Actions[i].Argv = append([]string{}, v.Actions[i].Argv...)
		}
		if v.Actions[i].Files != nil {
			out.Actions[i].Files = append([]FilePin{}, v.Actions[i].Files...)
		}
	}
	return out
}
func CloneRuntime(v RuntimeDocument) RuntimeDocument {
	out := v
	out.Driver = v.Driver
	if v.Files != nil {
		out.Files = make([]RuntimeFile, len(v.Files))
		copy(out.Files, v.Files)
	}
	for i := range out.Files {
		if v.Files[i].Chunks != nil {
			out.Files[i].Chunks = append([]ChunkPin{}, v.Files[i].Chunks...)
		}
	}
	return out
}

func decodeClosed(raw []byte, max int, fields []string, dst any) error {
	if len(raw) == 0 || len(raw) > max {
		return errors.New("envcontract: wire size limit")
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return err
	}
	if string(canonical) != string(raw) {
		return errors.New("envcontract: noncanonical JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	if len(object) != len(fields) {
		return errors.New("envcontract: unknown or missing field")
	}
	for _, f := range fields {
		if _, ok := object[f]; !ok {
			return fmt.Errorf("envcontract: missing field %s", f)
		}
	}
	return canonicaljson.DecodeStrict(raw, dst)
}

func validateSourceSnapshot(s SourceSnapshot) error {
	if err := validatePath(s.ManifestPath); err != nil || !validDigest(s.ManifestSHA256) {
		return errors.New("envcontract: invalid manifest snapshot pin")
	}
	if len(s.Files) == 0 || len(s.Files) > MaxSourceFiles {
		return errors.New("envcontract: invalid source file count")
	}
	seen := map[string]bool{}
	paths := make([]string, 0, len(s.Files))
	total := int64(0)
	manifestFound := false
	for _, f := range s.Files {
		if err := validateFilePin(FilePin{Path: f.Path, Mode: f.Mode, SHA256: f.SHA256}); err != nil || len(f.Bytes) > MaxSourceFileBytes {
			return errors.New("envcontract: invalid source snapshot file")
		}
		if f.Mode != "100644" {
			return errors.New("envcontract: source snapshot mode must be 100644")
		}
		if seen[f.Path] {
			return fmt.Errorf("envcontract: duplicate source path %q", f.Path)
		}
		seen[f.Path] = true
		paths = append(paths, f.Path)
		if Digest(f.Bytes) != f.SHA256 {
			return fmt.Errorf("envcontract: source digest mismatch for %q", f.Path)
		}
		total += int64(len(f.Bytes))
		if f.Path == s.ManifestPath {
			manifestFound = f.SHA256 == s.ManifestSHA256
		}
	}
	if err := validatePathSet(paths); err != nil {
		return err
	}
	if total > MaxSourceTotalBytes || !manifestFound {
		return errors.New("envcontract: incomplete source snapshot")
	}
	return nil
}

func validateAction(a *Action) error {
	if err := validateToken(a.Name, MaxNameBytes); err != nil {
		return err
	}
	if err := validatePath(a.PlaybookFile); err != nil {
		return err
	}
	if len(a.Files) == 0 || !sort.SliceIsSorted(a.Files, func(i, j int) bool { return a.Files[i].Path < a.Files[j].Path }) {
		return errors.New("envcontract: invalid action file pins")
	}
	if err := validatePath(a.RuntimeIndexPath); err != nil || !validDigest(a.RuntimeIndexSHA256) {
		return errors.New("envcontract: invalid runtime index reference")
	}
	if len(a.Argv) == 0 || len(a.Argv) > MaxArgvItems || a.TimeoutMillis < 1 || a.TimeoutMillis > 3600000 || a.ExecutionProfile != ExecutionProfile || a.Effects != HostEffects {
		return errors.New("envcontract: invalid action execution metadata")
	}
	argvTotal := 0
	for _, arg := range a.Argv {
		if err := validateArg(arg, MaxArgvItemBytes); err != nil {
			return errors.New("envcontract: invalid action argv")
		}
		argvTotal += len(arg)
	}
	if argvTotal > MaxArgvTotalBytes {
		return errors.New("envcontract: action argv exceeds aggregate bound")
	}
	if err := validatePath(a.InventoryPath); err != nil {
		return errors.New("envcontract: invalid action input path")
	}
	if err := validatePath(a.ConfigPath); err != nil {
		return errors.New("envcontract: invalid action input path")
	}
	return nil
}

func validateFilePin(f FilePin) error {
	if err := validatePath(f.Path); err != nil {
		return err
	}
	if f.Mode != "100644" && f.Mode != "100755" {
		return errors.New("envcontract: invalid file mode")
	}
	if !validDigest(f.SHA256) {
		return errors.New("envcontract: invalid file digest")
	}
	return nil
}
func validateName(s string) error {
	return validateToken(s, MaxNameBytes)
}
func validatePath(s string) error {
	if err := exports.ValidatePortablePath(s); err != nil {
		return fmt.Errorf("envcontract: invalid relative path %q", s)
	}
	return nil
}
func validDigest(s string) bool {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	digest := s[len("sha256:"):]
	if strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func validPlatform(goos, goarch string) bool {
	return (goos == "darwin" && goarch == "arm64") || (goos == "linux" && (goarch == "amd64" || goarch == "arm64"))
}

func validateToken(s string, max int) error {
	if s == "" || len(s) > max {
		return errors.New("envcontract: invalid token")
	}
	for i, r := range s {
		if r > 0x7f || r == 0 || r < 0x21 || !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') || (i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')) {
			return errors.New("envcontract: invalid token")
		}
	}
	return nil
}

func validateArg(s string, max int) error {
	if s == "" || len(s) > max {
		return errors.New("envcontract: invalid argv item")
	}
	for _, r := range s {
		if r == 0 || r < 0x20 || r == 0x7f {
			return errors.New("envcontract: invalid argv item")
		}
	}
	return nil
}

func validatePathSet(paths []string) error {
	for i := range paths {
		left := foldPortablePath(paths[i])
		for j := i + 1; j < len(paths); j++ {
			right := foldPortablePath(paths[j])
			if left == right || strings.HasPrefix(right, left+"/") || strings.HasPrefix(left, right+"/") {
				return fmt.Errorf("envcontract: colliding or ancestor paths %q and %q", paths[i], paths[j])
			}
		}
	}
	return nil
}

// foldPortablePath mirrors exports/materialize.go's fixed Unicode SimpleFold
// representative so admission and later portable materialization agree.
func foldPortablePath(path string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, path)
}
func snapshotFile(files []SnapshotFile, path string) (SnapshotFile, bool) {
	for _, f := range files {
		if f.Path == path {
			return f, true
		}
	}
	return SnapshotFile{}, false
}
