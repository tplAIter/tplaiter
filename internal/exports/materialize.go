package exports

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
)

const ExportPayloadAPIVersion = "tplaiter.dev/export-payload/v1"

var (
	materialDigestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	materialIDRE       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
	materialProviderRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._/-]{0,127}$`)
	materialAliasRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
	materialVersionRE  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+][0-9A-Za-z.-]+)?$`)
)

type ExportPayload struct {
	APIVersion string         `json:"apiVersion"`
	ExportID   string         `json:"exportID"`
	Files      []PayloadFile  `json:"files"`
	Slots      []PayloadSlot  `json:"slots"`
	Blocks     []PayloadBlock `json:"blocks"`
}
type PayloadFile struct {
	SourcePath    string `json:"sourcePath"`
	TargetPath    string `json:"targetPath"`
	Mode          string `json:"mode"`
	ContentSHA256 string `json:"contentSHA256"`
}
type PayloadSlot struct {
	TargetPath string `json:"targetPath"`
	Pointer    string `json:"pointer"`
	Value      string `json:"value"`
}
type PayloadBlock struct {
	SourcePath    string `json:"sourcePath"`
	ContentSHA256 string `json:"contentSHA256"`
}

type MaterialError struct{ Code, Path, Pointer string }

func (e *MaterialError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

type FormatError struct{ Code, Path, Pointer string }

func (e *FormatError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

func ferr(code, path, ptr string) error { return &FormatError{Code: code, Path: path, Pointer: ptr} }

func merr(code, path, ptr string) error { return &MaterialError{Code: code, Path: path, Pointer: ptr} }

func ParseExportPayload(raw []byte) (ExportPayload, error) {
	var p ExportPayload
	if len(raw) == 0 || len(raw) > 1<<20 {
		return p, ferr("MATERIAL_LIMIT", "", "")
	}
	var fields map[string]json.RawMessage
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return p, ferr("MATERIAL_PAYLOAD", "", "")
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return p, ferr("MATERIAL_PAYLOAD", "", "")
	}
	for _, k := range []string{"apiVersion", "exportID", "files", "slots", "blocks"} {
		if _, ok := fields[k]; !ok {
			return p, ferr("MATERIAL_PAYLOAD", "", "")
		}
	}
	if len(fields) != 5 {
		return p, ferr("MATERIAL_PAYLOAD", "", "")
	}
	if err := canonicaljson.DecodeStrict(raw, &p); err != nil {
		return p, ferr("MATERIAL_PAYLOAD", "", "")
	}
	if p.APIVersion != ExportPayloadAPIVersion || !materialIDRE.MatchString(p.ExportID) || p.Files == nil || p.Slots == nil || p.Blocks == nil {
		return ExportPayload{}, ferr("MATERIAL_PAYLOAD", "", "")
	}
	if len(p.Files)+len(p.Slots)+len(p.Blocks) == 0 || len(p.Files)+len(p.Slots)+len(p.Blocks) > 4096 {
		return ExportPayload{}, ferr("MATERIAL_LIMIT", "", "")
	}
	seenTarget := map[string]bool{}
	seenSource := map[string]bool{}
	for i := range p.Files {
		f := &p.Files[i]
		if err := payloadPath(f.SourcePath); err != nil {
			return ExportPayload{}, err
		}
		if err := payloadPath(f.TargetPath); err != nil {
			return ExportPayload{}, err
		}
		if f.Mode != "100644" && f.Mode != "100755" || !materialDigestRE.MatchString(f.ContentSHA256) || seenTarget[foldPath(f.TargetPath)] || seenSource[f.SourcePath] {
			return ExportPayload{}, ferr("MATERIAL_PAYLOAD", f.TargetPath, "")
		}
		seenTarget[foldPath(f.TargetPath)] = true
		seenSource[f.SourcePath] = true
	}
	seenSlot := map[string]bool{}
	for i := range p.Slots {
		s := &p.Slots[i]
		if err := payloadPath(s.TargetPath); err != nil {
			return ExportPayload{}, err
		}
		if err := slotPointer(s.Pointer); err != nil {
			return ExportPayload{}, err
		}
		decoded, err := decodePointer(s.Pointer)
		if err != nil || len(s.Value) > 64<<10 || seenTarget[foldPath(s.TargetPath)] || seenSlot[foldPath(s.TargetPath)+"\x00"+decoded] {
			return ExportPayload{}, ferr("MATERIAL_PAYLOAD", s.TargetPath, s.Pointer)
		}
		seenSlot[foldPath(s.TargetPath)+"\x00"+decoded] = true
	}
	for i := range p.Blocks {
		b := &p.Blocks[i]
		if err := payloadPath(b.SourcePath); err != nil {
			return ExportPayload{}, err
		}
		if !materialDigestRE.MatchString(b.ContentSHA256) || seenSource[b.SourcePath] {
			return ExportPayload{}, ferr("MATERIAL_PAYLOAD", b.SourcePath, "")
		}
		seenSource[b.SourcePath] = true
	}
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].TargetPath < p.Files[j].TargetPath })
	sort.Slice(p.Slots, func(i, j int) bool {
		if p.Slots[i].TargetPath != p.Slots[j].TargetPath {
			return p.Slots[i].TargetPath < p.Slots[j].TargetPath
		}
		a, _ := decodePointer(p.Slots[i].Pointer)
		b, _ := decodePointer(p.Slots[j].Pointer)
		return a < b
	})
	sort.Slice(p.Blocks, func(i, j int) bool { return p.Blocks[i].SourcePath < p.Blocks[j].SourcePath })
	return p, nil
}

func payloadPath(s string) error {
	if s == "" || len(s) > 4096 || utf8.RuneCountInString(s) > 1024 || !utf8.ValidString(s) || strings.HasPrefix(s, "/") || strings.ContainsAny(s, `\\:`) || strings.Contains(s, "//") || strings.HasSuffix(s, "/") {
		return ferr("MATERIAL_PATH", s, "")
	}
	for _, c := range strings.Split(s, "/") {
		if c == "." || c == ".." || c == "" || strings.EqualFold(c, ".git") || strings.EqualFold(c, ".tplater") || strings.EqualFold(c, ".tplaiter") || windowsDevice(c) || strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return ferr("MATERIAL_PATH", s, "")
		}
		for _, r := range c {
			if unicode.IsControl(r) {
				return ferr("MATERIAL_PATH", s, "")
			}
		}
	}
	return nil
}

// windowsDevice rejects the reserved names on every platform.  The payload
// identity is platform-independent, so accepting a name that cannot be
// materialized on Windows would make a sealed payload non-portable.
func windowsDevice(s string) bool {
	base := strings.ToUpper(strings.SplitN(s, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9'
}

func foldPath(s string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < min {
				min = next
			}
		}
		return min
	}, s)
}

func slotPointer(s string) error {
	if len(s) == 0 || len(s) > 4096 || !utf8.ValidString(s) || !strings.HasPrefix(s, "/") {
		return ferr("MATERIAL_PATH", "", s)
	}
	parts := strings.Split(s, "/")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return ferr("MATERIAL_PATH", "", s)
	}
	decodePart := func(part string) (string, bool) {
		var b strings.Builder
		for i := 0; i < len(part); i++ {
			if part[i] != '~' {
				b.WriteByte(part[i])
				continue
			}
			if i+1 >= len(part) || (part[i+1] != '0' && part[i+1] != '1') {
				return "", false
			}
			if part[i+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			i++
		}
		return b.String(), true
	}
	root, okRoot := decodePart(parts[1])
	key, okKey := decodePart(parts[2])
	if !okRoot || !okKey || !slotRoots[root] || key == "*" || "/"+escapePointer(root)+"/"+escapePointer(key) != s {
		return ferr("MATERIAL_PATH", "", s)
	}
	return nil
}

func decodePointer(s string) (string, error) {
	if len(s) == 0 || len(s) > 4096 || !utf8.ValidString(s) || !strings.HasPrefix(s, "/") {
		return "", ferr("MATERIAL_PATH", "", s)
	}
	parts := strings.Split(s, "/")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", ferr("MATERIAL_PATH", "", s)
	}
	decoded := make([]string, 0, 2)
	for _, x := range parts[1:] {
		var b strings.Builder
		for i := 0; i < len(x); i++ {
			if x[i] != '~' {
				b.WriteByte(x[i])
				continue
			}
			if i+1 >= len(x) || (x[i+1] != '0' && x[i+1] != '1') {
				return "", ferr("MATERIAL_PATH", "", s)
			}
			if x[i+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			i++
		}
		v := b.String()
		if v == "" {
			return "", ferr("MATERIAL_PATH", "", s)
		}
		decoded = append(decoded, v)
	}
	if "/"+escapePointer(decoded[0])+"/"+escapePointer(decoded[1]) != s {
		return "", ferr("MATERIAL_PATH", "", s)
	}
	return decoded[0] + "/" + decoded[1], nil
}
func escapePointer(s string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }
func digestBytes(b []byte) string   { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

type MaterialSource struct {
	Selected SelectedExport
	Payload  []byte
	Blobs    []MaterialBlob
}
type MaterialBlob struct {
	Path, Mode string
	Content    []byte
}
type (
	MaterialOwner struct{ Provider, RuleID, ExportID string }
	FileState     struct {
		Path                string
		Present             bool
		Mode, ContentSHA256 string
		Content             []byte
	}
)

type OwnedPreimage struct {
	Path, Pointer       string
	Owner               MaterialOwner
	Mode, ContentSHA256 string
}
type MaterialOperation struct {
	Kind, Path, Pointer          string
	BeforeOwner, AfterOwner      MaterialOwner
	ExpectedMode, ExpectedSHA256 string
	SourceIndex, EntryIndex      int
}
type ManagedCandidate struct {
	Plan                      managedblocks.FilePlan
	Before                    FileState
	BeforeOwners, AfterOwners []MaterialOwner
	DesiredMode               string
}
type (
	InventoryEntry   struct{ Path, Kind string }
	MaterializeInput struct {
		Sources         []MaterialSource
		TargetInventory []InventoryEntry
		Current         []FileState
		Owned           []OwnedPreimage
		Operations      []MaterialOperation
		Managed         []ManagedCandidate
	}
)

type FileImage struct {
	Path                      string
	Before, After             FileState
	BeforeOwners, AfterOwners []MaterialOwner
	Reason                    string
	FormattingOnly            bool
}
type (
	MaterialConflict struct{ Code, Path, Pointer string }
	Materialization  struct {
		Images    []FileImage
		Conflicts []MaterialConflict
		Managed   []managedblocks.FilePlan
	}
)

type JSONSlotMutation struct {
	Kind, Pointer                       string
	BeforeOwner, AfterOwner             MaterialOwner
	ExpectedMode, ExpectedSHA256, Value string
}

func Materialize(in MaterializeInput) (Materialization, error) {
	out := Materialization{Images: []FileImage{}, Conflicts: []MaterialConflict{}, Managed: []managedblocks.FilePlan{}}
	if in.Sources == nil || in.TargetInventory == nil || in.Current == nil || in.Owned == nil || in.Operations == nil || in.Managed == nil {
		return Materialization{}, merr("MATERIAL_INPUT", "", "")
	}
	if len(in.Current)+len(in.Operations)+len(in.Managed) > 4096 {
		return Materialization{}, merr("MATERIAL_LIMIT", "", "")
	}
	entries := map[[2]int]PayloadFile{}
	slotEntries := map[[2]int]PayloadSlot{}
	blobContents := map[[2]int]MaterialBlob{}
	selectedBySource := map[int]SelectedExport{}
	sourceRedirect := map[int]int{}
	selectedIdentity := map[string]int{}
	sourceContent := map[int]string{}
	seenPaths := map[string]string{}
	inventory := map[string]InventoryEntry{}
	for i, e := range in.TargetInventory {
		if i > 0 && in.TargetInventory[i-1].Path >= e.Path {
			return Materialization{}, merr("MATERIAL_INPUT", e.Path, "")
		}
		if err := payloadPath(e.Path); err != nil {
			return out, err
		}
		k := foldPath(e.Path)
		if old, ok := seenPaths[k]; ok && old != e.Path {
			return out, merr("MATERIAL_TARGET_CONFLICT", e.Path, "")
		}
		seenPaths[k] = e.Path
		if e.Kind != "regular" && e.Kind != "directory" && e.Kind != "symlink" && e.Kind != "other" {
			return Materialization{}, merr("MATERIAL_INPUT", e.Path, "")
		}
		if _, exists := inventory[e.Path]; exists {
			return Materialization{}, merr("MATERIAL_TARGET_CONFLICT", e.Path, "")
		}
		inventory[e.Path] = e
	}
	cur := map[string]FileState{}
	for _, f := range in.Current {
		if err := payloadPath(f.Path); err != nil {
			return out, err
		}
		if _, ok := cur[f.Path]; ok {
			return out, merr("MATERIAL_TARGET_CONFLICT", f.Path, "")
		}
		c := append([]byte(nil), f.Content...)
		f.Content = c
		if !f.Present && (f.Mode != "" || f.ContentSHA256 != "" || len(c) != 0) {
			return Materialization{}, merr("MATERIAL_INPUT", f.Path, "")
		}
		if f.Present && (f.Mode != "100644" && f.Mode != "100755" || digestBytes(c) != f.ContentSHA256) {
			return Materialization{}, merr("MATERIAL_INPUT", f.Path, "")
		}
		if f.Present && inventory[f.Path].Kind != "regular" {
			return Materialization{}, merr("MATERIAL_INPUT", f.Path, "")
		}
		cur[f.Path] = f
	}
	for path, entry := range inventory {
		if entry.Kind == "regular" {
			if state, ok := cur[path]; !ok || !state.Present {
				return Materialization{}, merr("MATERIAL_INPUT", path, "")
			}
		}
	}
	var totalBlobBytes uint64
	for si, s := range in.Sources {
		identity, identityErr := SelectedExportIdentity(s.Selected)
		if identityErr != nil || validateSelected(s.Selected) != nil {
			return Materialization{}, merr("MATERIAL_BINDING", "", "")
		}
		selectedBySource[si] = s.Selected
		p, e := ParseExportPayload(s.Payload)
		if e != nil {
			return out, e
		}
		if p.ExportID != s.Selected.ID || !materialDigestRE.MatchString(s.Selected.ContentDigest) || digestBytes(s.Payload) != s.Selected.ContentDigest {
			return out, merr("MATERIAL_BINDING", "", "")
		}
		sourceBlobs := map[string]MaterialBlob{}
		for _, b := range s.Blobs {
			if err := payloadPath(b.Path); err != nil {
				return out, err
			}
			if _, ok := sourceBlobs[b.Path]; ok {
				return out, merr("MATERIAL_PAYLOAD", b.Path, "")
			}
			if len(b.Content) > 16<<20 || b.Mode != "100644" && b.Mode != "100755" {
				return out, merr("MATERIAL_INPUT", b.Path, "")
			}
			totalBlobBytes += uint64(len(b.Content))
			if totalBlobBytes > 64<<20 {
				return Materialization{}, merr("MATERIAL_LIMIT", b.Path, "")
			}
			sourceBlobs[b.Path] = MaterialBlob{Path: b.Path, Mode: b.Mode, Content: append([]byte(nil), b.Content...)}
		}
		for ei, f := range p.Files {
			entries[[2]int{si, ei}] = f
			b, ok := sourceBlobs[f.SourcePath]
			if !ok || digestBytes(b.Content) != f.ContentSHA256 {
				return out, merr("MATERIAL_INPUT", f.TargetPath, "")
			}
			if b.Mode != f.Mode {
				return out, merr("MATERIAL_INPUT", f.TargetPath, "")
			}
			blobContents[[2]int{si, ei}] = b
		}
		for ei, s := range p.Slots {
			slotEntries[[2]int{si, ei}] = s
		}
		if len(sourceBlobs) != len(p.Files) {
			return out, merr("MATERIAL_INPUT", "", "")
		}
		if len(p.Blocks) > 0 {
			return out, merr("MATERIAL_UNSUPPORTED", "", "")
		}
		// Every supplied record is parsed and its blobs bound before exact
		// duplicates are coalesced. A duplicate cannot hide malformed bytes.
		sig := s.Selected.ContentDigest
		for _, b := range s.Blobs {
			sig += "\x00" + b.Path + "\x00" + b.Mode + "\x00" + digestBytes(b.Content)
		}
		if first, duplicate := selectedIdentity[s.Selected.Source]; duplicate {
			firstIdentity, _ := SelectedExportIdentity(selectedBySource[first])
			if identity != firstIdentity || sig != sourceContent[first] {
				return Materialization{}, merr("MATERIAL_BINDING", "", "")
			}
			sourceRedirect[si] = first
		} else {
			selectedIdentity[s.Selected.Source] = si
			sourceContent[si] = sig
			sourceRedirect[si] = si
		}
	}
	owned := map[string]OwnedPreimage{}
	ownedSlots := make([]OwnedPreimage, 0)
	ownedSlotKeys := map[string]bool{}
	for _, o := range in.Owned {
		if err := payloadPath(o.Path); err != nil || !validOwner(o.Owner) || (o.Pointer != "" && slotPointer(o.Pointer) != nil) {
			return Materialization{}, merr("MATERIAL_INPUT", o.Path, o.Pointer)
		}
		if o.Pointer == "" && (!materialDigestRE.MatchString(o.ContentSHA256) || (o.Mode != "100644" && o.Mode != "100755")) {
			return Materialization{}, merr("MATERIAL_INPUT", o.Path, "")
		}
		if o.Pointer != "" {
			rootName, _, pointerErr := slotPointerParts(o.Pointer)
			if pointerErr != nil || !slotRoots[rootName] || !materialDigestRE.MatchString(o.ContentSHA256) || (o.Mode != "100644" && o.Mode != "100755") {
				return Materialization{}, merr("MATERIAL_INPUT", o.Path, o.Pointer)
			}
			key := slotMutationKey(o.Path, o.Pointer)
			if ownedSlotKeys[key] {
				return Materialization{}, merr("MATERIAL_INPUT", o.Path, o.Pointer)
			}
			ownedSlotKeys[key] = true
			ownedSlots = append(ownedSlots, o)
		} else {
			if _, exists := owned[o.Path]; exists {
				return Materialization{}, merr("MATERIAL_INPUT", o.Path, "")
			}
			owned[o.Path] = o
		}
	}
	managedPaths := map[string]bool{}
	for _, m := range in.Managed {
		if err := payloadPath(m.Plan.Path); err != nil || m.Plan.Path != m.Before.Path || !m.Before.Present || m.DesiredMode != m.Before.Mode || (m.DesiredMode != "100644" && m.DesiredMode != "100755") {
			return Materialization{}, merr("MATERIAL_INPUT", m.Plan.Path, "")
		}
		actual, ok := cur[m.Plan.Path]
		if !ok || actual.Mode != m.Before.Mode || actual.ContentSHA256 != m.Before.ContentSHA256 || !bytes.Equal(actual.Content, m.Before.Content) || managedPaths[m.Plan.Path] {
			return Materialization{}, merr("MATERIAL_TARGET_CONFLICT", m.Plan.Path, "")
		}
		managedPaths[m.Plan.Path] = true
		out.Managed = append(out.Managed, cloneManagedPlan(m.Plan))
	}
	for _, op := range in.Operations {
		if err := payloadPath(op.Path); err != nil {
			return Materialization{}, merr("MATERIAL_INPUT", op.Path, op.Pointer)
		}
		if managedPaths[op.Path] {
			return Materialization{}, merr("MATERIAL_TARGET_CONFLICT", op.Path, "")
		}
		k := foldPath(op.Path)
		if old, ok := seenPaths[k]; ok && old != op.Path {
			return out, merr("MATERIAL_TARGET_CONFLICT", op.Path, "")
		}
		seenPaths[k] = op.Path
		if op.Pointer != "" {
			if err := slotPointer(op.Pointer); err != nil {
				return Materialization{}, merr("MATERIAL_INPUT", op.Path, op.Pointer)
			}
			if op.Kind == "remove" {
				if op.SourceIndex != -1 || op.EntryIndex != -1 || op.AfterOwner != (MaterialOwner{}) {
					return Materialization{}, merr("MATERIAL_INPUT", op.Path, op.Pointer)
				}
			} else {
				slot, found := slotEntries[[2]int{sourceRedirect[op.SourceIndex], op.EntryIndex}]
				sel, selOK := selectedBySource[op.SourceIndex]
				if !found || !selOK || slot.TargetPath != op.Path || slot.Pointer != op.Pointer || !validOwner(op.AfterOwner) || op.AfterOwner.Provider != sel.Provider || op.AfterOwner.ExportID != sel.ID {
					return Materialization{}, merr("MATERIAL_OWNER_CONFLICT", op.Path, op.Pointer)
				}
			}
			continue
		}
		parts := strings.Split(op.Path, "/")
		for i := 1; i < len(parts); i++ {
			a := strings.Join(parts[:i], "/")
			if f, ok := cur[a]; ok && f.Present {
				return out, merr("MATERIAL_TARGET_CONFLICT", op.Path, "")
			}
			for _, e := range in.TargetInventory {
				if e.Path == a && e.Kind != "directory" {
					return out, merr("MATERIAL_TARGET_CONFLICT", op.Path, "")
				}
			}
		}
	}
	// A file cannot also be the parent of another requested image.  Check this
	// before any image is emitted so a malformed plan never gets a partial
	// materialization result.
	for i := range in.Operations {
		for j := range in.Operations {
			if i != j && strings.HasPrefix(in.Operations[j].Path, in.Operations[i].Path+"/") {
				return Materialization{}, merr("MATERIAL_TARGET_CONFLICT", in.Operations[j].Path, "")
			}
		}
	}
	seenOperations := map[string]bool{}
	for _, op := range in.Operations {
		if op.Pointer != "" {
			continue
		}
		if seenOperations[op.Path] {
			return Materialization{}, merr("MATERIAL_TARGET_CONFLICT", op.Path, "")
		}
		seenOperations[op.Path] = true
		if op.Kind != "add" && op.Kind != "replace" && op.Kind != "remove" {
			return Materialization{}, merr("MATERIAL_INPUT", op.Path, "")
		}
		before, ok := cur[op.Path]
		if !ok || (op.Kind == "add" && before.Present) {
			return Materialization{}, merr("MATERIAL_TARGET_CONFLICT", op.Path, "")
		}
		if op.Kind == "add" {
			if op.BeforeOwner != (MaterialOwner{}) || op.ExpectedMode != "" || op.ExpectedSHA256 != "" {
				return Materialization{}, merr("MATERIAL_INPUT", op.Path, "")
			}
		} else if !materialPreimage(op) {
			return Materialization{}, merr("MATERIAL_INPUT", op.Path, "")
		}
		if op.Kind == "remove" {
			if op.AfterOwner != (MaterialOwner{}) || op.SourceIndex != -1 || op.EntryIndex != -1 {
				return Materialization{}, merr("MATERIAL_INPUT", op.Path, "")
			}
			continue
		}
		if !validOwner(op.AfterOwner) {
			return Materialization{}, merr("MATERIAL_OWNER_CONFLICT", op.Path, "")
		}
		sel, ok := selectedBySource[op.SourceIndex]
		f, found := entries[[2]int{sourceRedirect[op.SourceIndex], op.EntryIndex}]
		if !ok || !found || f.TargetPath != op.Path || op.AfterOwner.Provider != sel.Provider || op.AfterOwner.ExportID != sel.ID {
			return Materialization{}, merr("MATERIAL_OWNER_CONFLICT", op.Path, "")
		}
	}
	for _, op := range in.Operations {
		if op.Pointer != "" {
			continue
		}
		if op.Kind != "add" && op.Kind != "replace" && op.Kind != "remove" {
			return out, merr("MATERIAL_INPUT", op.Path, "")
		}
		before, ok := cur[op.Path]
		if !ok {
			return out, merr("MATERIAL_INPUT", op.Path, "")
		}
		if op.Kind == "add" && before.Present {
			return out, merr("MATERIAL_TARGET_CONFLICT", op.Path, "")
		}
		if op.Kind == "add" {
			if _, exists := owned[op.Path]; exists {
				out.Images = append(out.Images, conflictImage(op, before, "MATERIAL_OWNER_CONFLICT"))
				out.Conflicts = append(out.Conflicts, MaterialConflict{Code: "MATERIAL_OWNER_CONFLICT", Path: op.Path})
				continue
			}
		}
		if op.Kind != "add" && !before.Present {
			out.Images = append(out.Images, conflictImage(op, before, "MATERIAL_PREIMAGE_CONFLICT"))
			out.Conflicts = append(out.Conflicts, MaterialConflict{Code: "MATERIAL_PREIMAGE_CONFLICT", Path: op.Path})
			continue
		}
		if op.Kind != "add" {
			prior, hasPrior := owned[op.Path]
			if !hasPrior || prior.Owner != op.BeforeOwner || op.BeforeOwner == (MaterialOwner{}) {
				out.Images = append(out.Images, conflictImage(op, before, "MATERIAL_OWNER_CONFLICT"))
				out.Conflicts = append(out.Conflicts, MaterialConflict{Code: "MATERIAL_OWNER_CONFLICT", Path: op.Path})
				continue
			}
			if prior.Mode != op.ExpectedMode || prior.ContentSHA256 != op.ExpectedSHA256 || prior.Mode != before.Mode || prior.ContentSHA256 != before.ContentSHA256 {
				out.Images = append(out.Images, conflictImage(op, before, "MATERIAL_PREIMAGE_CONFLICT"))
				out.Conflicts = append(out.Conflicts, MaterialConflict{Code: "MATERIAL_PREIMAGE_CONFLICT", Path: op.Path})
				continue
			}
		}
		if op.Kind == "add" && op.BeforeOwner != (MaterialOwner{}) {
			return out, merr("MATERIAL_OWNER_CONFLICT", op.Path, "")
		}
		if op.Kind != "remove" {
			sel, ok := selectedBySource[op.SourceIndex]
			if !ok || op.AfterOwner.Provider != sel.Provider || op.AfterOwner.ExportID != sel.ID {
				return out, merr("MATERIAL_OWNER_CONFLICT", op.Path, "")
			}
		}
		if op.AfterOwner == (MaterialOwner{}) && op.Kind != "remove" {
			return out, merr("MATERIAL_OWNER_CONFLICT", op.Path, "")
		}
		if op.Kind != "add" && (op.ExpectedMode != before.Mode || op.ExpectedSHA256 != before.ContentSHA256) {
			out.Images = append(out.Images, conflictImage(op, before, "MATERIAL_PREIMAGE_CONFLICT"))
			out.Conflicts = append(out.Conflicts, MaterialConflict{Code: "MATERIAL_PREIMAGE_CONFLICT", Path: op.Path})
			continue
		}
		after := FileState{Path: op.Path, Present: op.Kind != "remove"}
		if after.Present {
			f, found := entries[[2]int{sourceRedirect[op.SourceIndex], op.EntryIndex}]
			b, hasBlob := blobContents[[2]int{sourceRedirect[op.SourceIndex], op.EntryIndex}]
			if !found || !hasBlob || f.TargetPath != op.Path {
				return out, merr("MATERIAL_INPUT", op.Path, "")
			}
			after.Mode, after.ContentSHA256 = f.Mode, f.ContentSHA256
			after.Content = append([]byte(nil), b.Content...)
		}
		if op.Kind == "remove" {
			after.Mode = ""
			after.ContentSHA256 = ""
		}
		out.Images = append(out.Images, FileImage{Path: op.Path, Before: cloneState(before), After: after, BeforeOwners: cloneOwners(op.BeforeOwner), AfterOwners: cloneOwners(op.AfterOwner), Reason: op.Kind})
	}
	byPath := map[string][]JSONSlotMutation{}
	for _, op := range in.Operations {
		if op.Pointer == "" {
			continue
		}
		value := ""
		if op.Kind != "remove" {
			slot := slotEntries[[2]int{sourceRedirect[op.SourceIndex], op.EntryIndex}]
			value = slot.Value
		}
		byPath[op.Path] = append(byPath[op.Path], JSONSlotMutation{Kind: op.Kind, Pointer: op.Pointer, BeforeOwner: op.BeforeOwner, AfterOwner: op.AfterOwner, ExpectedMode: op.ExpectedMode, ExpectedSHA256: op.ExpectedSHA256, Value: value})
	}
	for path, mutations := range byPath {
		if seenOperations[path] {
			return Materialization{}, merr("MATERIAL_TARGET_CONFLICT", path, "")
		}
		state, ok := cur[path]
		if !ok {
			return Materialization{}, merr("MATERIAL_INPUT", path, "")
		}
		image, conflicts, err := PlanJSONSlots(state, ownedSlots, mutations)
		if err != nil {
			return Materialization{}, err
		}
		if image.Path != "" {
			out.Images = append(out.Images, image)
		}
		out.Conflicts = append(out.Conflicts, conflicts...)
	}
	sort.Slice(out.Images, func(i, j int) bool { return out.Images[i].Path < out.Images[j].Path })
	sortSlotConflicts(out.Conflicts)
	return out, nil
}

func cloneManagedPlan(p managedblocks.FilePlan) managedblocks.FilePlan {
	p.Candidate = append([]byte(nil), p.Candidate...)
	p.Conflicts = append([]managedblocks.BlockConflict(nil), p.Conflicts...)
	p.RenameAliases = maps.Clone(p.RenameAliases)
	p.Baseline.Blocks = maps.Clone(p.Baseline.Blocks)
	for id, block := range p.Baseline.Blocks {
		if block.Tombstone != nil {
			tomb := *block.Tombstone
			block.Tombstone = &tomb
			p.Baseline.Blocks[id] = block
		}
	}
	return p
}

func validOwner(o MaterialOwner) bool {
	return exportTokenRE.MatchString(o.Provider) && exportAliasRE.MatchString(o.RuleID) && exportTokenRE.MatchString(o.ExportID)
}

func materialPreimage(op MaterialOperation) bool {
	return (op.ExpectedMode == "100644" || op.ExpectedMode == "100755") && materialDigestRE.MatchString(op.ExpectedSHA256)
}

func conflictImage(op MaterialOperation, before FileState, code string) FileImage {
	return FileImage{Path: op.Path, Before: cloneState(before), After: cloneState(before), BeforeOwners: cloneOwners(op.BeforeOwner), AfterOwners: cloneOwners(op.BeforeOwner), Reason: code}
}

func validateSelected(s SelectedExport) error {
	if !exportDigestRE.MatchString(s.Source) || !exportTokenRE.MatchString(s.Provider) || !exportTokenRE.MatchString(s.ID) || !exportAliasRE.MatchString(s.Name) || !strictSemver(s.Version) || !exportDigestRE.MatchString(s.ContentDigest) || !exportDigestRE.MatchString(s.ContractDigest) || !exportDigestRE.MatchString(s.BindingSHA256) || !exportDigestRE.MatchString(s.SourceParameterSHA256) || !exportDigestRE.MatchString(s.ToolDigest) || s.Parameters == nil || s.Chains == nil || !domainRankOK(s.Domain) || validateParams(s.Parameters) != nil {
		return merr("MATERIAL_BINDING", "", "")
	}
	for _, chain := range s.Chains {
		if len(chain) > maxExportDependencyDepth {
			return merr("MATERIAL_BINDING", "", "")
		}
	}
	switch s.Domain {
	case "block", "skill", "approach", "package":
	default:
		return merr("MATERIAL_BINDING", "", "")
	}
	if _, err := SelectedExportIdentity(s); err != nil {
		return merr("MATERIAL_BINDING", "", "")
	}
	return nil
}

// VersionMatches exposes the accepted modifier range grammar to formatter
// plan validation; it does not discover or authenticate installed tools.
func VersionMatches(version, constraint string) bool { return versionMatches(version, constraint) }
func ValidatePortablePath(path string) error         { return payloadPath(path) }
func cloneState(s FileState) FileState               { s.Content = append([]byte(nil), s.Content...); return s }

func cloneOwners(o MaterialOwner) []MaterialOwner {
	if o == (MaterialOwner{}) {
		return []MaterialOwner{}
	}
	return []MaterialOwner{o}
}
