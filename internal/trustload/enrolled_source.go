package trustload

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// The producer admits at most 32 packages, each with a <=1MiB publisher
// statement. Subject strings are drawn from that statement; the remaining
// selection fields are fixed hashes, a commit and empty dependencies.
const enrolledIndexLimit = 32 * ((1 << 20) + 4096)

type enrolledSubject struct {
	Origin         string `json:"origin"`
	TemplatePath   string `json:"templatePath"`
	RequestedRef   string `json:"requestedRef"`
	Commit         string `json:"commit"`
	TreeSHA256     string `json:"treeSHA256"`
	ContractSHA256 string `json:"contractSHA256"`
}
type enrolledEvidence struct {
	Format            string `json:"format"`
	StatementCAS      string `json:"statementCAS"`
	SignatureCAS      string `json:"signatureCAS"`
	KeyFingerprint    string `json:"keyFingerprint"`
	CheckpointCAS     string `json:"checkpointCAS"`
	InclusionProofCAS string `json:"inclusionProofCAS"`
}
type enrolledSelection struct {
	APIVersion   string           `json:"apiVersion"`
	Subject      enrolledSubject  `json:"subject"`
	Evidence     enrolledEvidence `json:"evidence"`
	Dependencies []string         `json:"dependencies"`
}

func (s enrolledSubject) subject() trustverify.Subject {
	return trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}

func (e enrolledEvidence) refs() trustverify.EvidenceRefs {
	return trustverify.EvidenceRefs{Format: e.Format, StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint, CheckpointCAS: e.CheckpointCAS, InclusionProofCAS: e.InclusionProofCAS}
}

func decodeEnrolledIndex(raw []byte) ([]enrolledSelection, error) {
	if len(raw) == 0 || len(raw) > enrolledIndexLimit {
		return nil, ErrConfigInvalid
	}
	var rows []enrolledSelection
	if canonicaljson.DecodeStrict(raw, &rows) != nil || len(rows) == 0 || len(rows) > 32 {
		return nil, ErrConfigInvalid
	}
	var objects []json.RawMessage
	if json.Unmarshal(raw, &objects) != nil {
		return nil, ErrConfigInvalid
	}
	seen := map[string]bool{}
	for i, s := range rows {
		var fields map[string]json.RawMessage
		if json.Unmarshal(objects[i], &fields) != nil || requiredObjectFields(objects[i], []string{"apiVersion", "subject", "evidence", "dependencies"}) != nil || requiredObjectFields(fields["subject"], []string{"origin", "templatePath", "requestedRef", "commit", "treeSHA256", "contractSHA256"}) != nil || requiredObjectFields(fields["evidence"], []string{"format", "statementCAS", "signatureCAS", "keyFingerprint", "checkpointCAS", "inclusionProofCAS"}) != nil {
			return nil, ErrConfigInvalid
		}
		if s.APIVersion != "tplaiter.dev/source-selection-input/v1" || s.Dependencies == nil || len(s.Dependencies) != 0 || s.Subject.Origin == "" || s.Subject.TemplatePath == "" || s.Subject.RequestedRef != s.Subject.Commit || (len(s.Subject.Commit) != 40 && len(s.Subject.Commit) != 64) || !digest(s.Subject.TreeSHA256) || !digest(s.Subject.ContractSHA256) || s.Evidence.Format != bootstrap.PublisherStatementAPIVersion || !digest(s.Evidence.StatementCAS) || !digest(s.Evidence.SignatureCAS) || !digest(s.Evidence.KeyFingerprint) || !digest(s.Evidence.CheckpointCAS) || !digest(s.Evidence.InclusionProofCAS) {
			return nil, ErrConfigInvalid
		}
		for _, c := range s.Subject.Commit {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return nil, ErrConfigInvalid
			}
		}
		// Grammar validation only, not verification or an operation grant.
		p := trustverify.Provider{Origin: s.Subject.Origin, TemplatePath: s.Subject.TemplatePath, Commit: s.Subject.Commit, TreeSHA256: s.Subject.TreeSHA256, ContractSHA256: s.Subject.ContractSHA256}
		if _, e := trustverify.ComputeOperationInputsSHA256(trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: s.Subject.TreeSHA256, ProjectID: "grammar", Scope: "run", PreimageSHA256: s.Subject.TreeSHA256, AnswersSHA256: s.Subject.TreeSHA256, Subjects: []trustverify.Provider{p}, Actions: []trustverify.ActionMaterial{}}); e != nil {
			return nil, ErrConfigInvalid
		}
		// Different proof or commit for the same source is ambiguous, too.
		key := s.Subject.Origin + "\x00" + s.Subject.TemplatePath
		if strings.ContainsRune(s.Subject.Origin, 0) || strings.ContainsRune(s.Subject.TemplatePath, 0) || seen[key] {
			return nil, ErrConfigInvalid
		}
		seen[key] = true
	}
	return rows, nil
}

// enrolledObservation retains original descriptors, every parent and body.
// os.Root confines opens; lstat/descriptor/membership checks refuse symlinks
// and replacements before and after every read rather than trusting a path.
type (
	enrolledObservation struct {
		root    *os.Root
		file    *os.File
		path    string
		info    os.FileInfo
		body    []byte
		parents []enrolledParent
	}
	enrolledParent struct {
		path string
		file *os.File
		info os.FileInfo
	}
)

func (o *enrolledObservation) close() {
	if o == nil {
		return
	}
	if o.file != nil {
		_ = o.file.Close()
	}
	if o.root != nil {
		_ = o.root.Close()
	}
	for _, p := range o.parents {
		_ = p.file.Close()
	}
}

func enrolledSame(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime() == b.ModTime() && reflect.DeepEqual(enrolledStat(a), enrolledStat(b))
}

func enrolledStat(info os.FileInfo) any {
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	copy := reflect.New(v.Type()).Elem()
	copy.Set(v)
	for _, name := range []string{"Atim", "Atimespec", "Atime", "Atimensec"} {
		f := copy.FieldByName(name)
		if f.IsValid() && f.CanSet() {
			f.SetZero()
		}
	}
	return copy.Interface()
}

func enrolledParentSame(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.IsDir() && b.IsDir() && os.SameFile(a, b) && a.Mode() == b.Mode()
}

func enrolledSingle(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return false
	}
	n := v.FieldByName("Nlink")
	return n.IsValid() && ((n.Kind() == reflect.Uint64 || n.Kind() == reflect.Uint32 || n.Kind() == reflect.Uint16) && n.Uint() == 1)
}

func holdEnrolledFile(ctx context.Context, path string, limit int) (*enrolledObservation, error) {
	if ctx == nil || ctx.Err() != nil || !absolutePath(path) {
		return nil, ErrPinMismatch
	}
	o := &enrolledObservation{path: path}
	good := false
	defer func() {
		if !good {
			o.close()
		}
	}()
	parent := filepath.Dir(path)
	parts := strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for _, part := range append([]string{""}, parts...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, e := os.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrPinMismatch
		}
		f, e := openEnrolledObserved(ctx, nil, current, info, true)
		if e != nil {
			return nil, ErrPinMismatch
		}
		actual, e := f.Stat()
		if e != nil || !enrolledParentSame(info, actual) {
			_ = f.Close()
			return nil, ErrPinMismatch
		}
		o.parents = append(o.parents, enrolledParent{current, f, actual})
	}
	info, e := os.Lstat(path)
	if e != nil || !enrolledSingle(info) || info.Size() < 1 || info.Size() > int64(limit) {
		return nil, ErrPinMismatch
	}
	o.root, e = enrolledRootFromDirectory(o.parents[len(o.parents)-1].file)
	if e != nil {
		return nil, ErrPinMismatch
	}
	rootInfo, e := o.root.Stat(".")
	if e != nil || !enrolledParentSame(o.parents[len(o.parents)-1].info, rootInfo) {
		return nil, ErrPinMismatch
	}
	o.file, e = openEnrolledObserved(ctx, o.root, filepath.Base(path), info, false)
	if e != nil {
		return nil, ErrPinMismatch
	}
	o.info, e = o.file.Stat()
	if e != nil || !enrolledSame(info, o.info) {
		return nil, ErrPinMismatch
	}
	o.body, e = io.ReadAll(io.LimitReader(o.file, int64(limit)+1))
	if e != nil || len(o.body) > limit || int64(len(o.body)) != info.Size() {
		return nil, ErrPinMismatch
	}
	if o.check(ctx) != nil {
		return nil, ErrPinMismatch
	}
	good = true
	return o, nil
}

func (o *enrolledObservation) check(ctx context.Context) error {
	if ctx == nil {
		return ErrPinMismatch
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	for _, p := range o.parents {
		a, e := p.file.Stat()
		b, e2 := os.Lstat(p.path)
		if e != nil || e2 != nil || !enrolledParentSame(p.info, a) || !enrolledParentSame(p.info, b) {
			return ErrPinMismatch
		}
	}
	a, e := o.file.Stat()
	b, e2 := os.Lstat(o.path)
	if e != nil || e2 != nil || !enrolledSingle(a) || !enrolledSame(o.info, a) || !enrolledSame(o.info, b) {
		return ErrPinMismatch
	}
	raw := make([]byte, len(o.body))
	n, e := o.file.ReadAt(raw, 0)
	if (e != nil && e != io.EOF) || n != len(raw) || !bytes.Equal(raw, o.body) {
		return ErrPinMismatch
	}
	a, e = o.file.Stat()
	b, e2 = os.Lstat(o.path)
	if e != nil || e2 != nil || !enrolledSame(o.info, a) || !enrolledSame(o.info, b) {
		return ErrPinMismatch
	}
	for _, p := range o.parents {
		a, e := p.file.Stat()
		b, e2 := os.Lstat(p.path)
		if e != nil || e2 != nil || !enrolledParentSame(p.info, a) || !enrolledParentSame(p.info, b) {
			return ErrPinMismatch
		}
	}
	return ctx.Err()
}

// ResolveEnrolledSource uses only the fixed installed index as untrusted proof
// transport. Immutable publisher identity must match before the current
// runtime verifies receipt, policy, signatures, transparency and Git CAS.
// It constructs no runtime, permit or execution authority.
func (r *Runtime) ResolveEnrolledSource(ctx context.Context, subject trustverify.Subject, publisher bootstrap.PublisherEvidence) (*trustverify.VerifiedResolution, error) {
	if r == nil || ctx == nil {
		return nil, ErrProvenanceUnavailable
	}
	stable := r.TrustRuntime()
	if stable == nil {
		return nil, ErrProvenanceUnavailable
	}
	binding := stable.Binding()
	loaded, e := Load(ctx, r.installation)
	if e != nil {
		return nil, e
	}
	paths := []string{r.installation.RuntimeConfig.Path, r.installation.OperatorRecord.Path, loaded.Install.Descriptor.Path, loaded.Install.Provisioning.Path, loaded.Install.ExecutionPolicy.Path, filepath.Join(filepath.Dir(r.installation.RuntimeConfig.Path), "source-selections.json")}
	holds := []*enrolledObservation{}
	defer func() {
		for _, h := range holds {
			h.close()
		}
	}()
	for i, path := range paths {
		limit := maxDocument
		if i == len(paths)-1 {
			limit = enrolledIndexLimit
		}
		h, e := holdEnrolledFile(ctx, path, limit)
		if e != nil {
			return nil, e
		}
		holds = append(holds, h)
	}
	check := func() error {
		if r.TrustRuntime() != stable {
			return ErrPinMismatch
		}
		if _, e := Load(ctx, r.installation); e != nil {
			return e
		}
		if e := stable.CheckBinding(binding); e != nil {
			return e
		}
		for _, h := range holds {
			if e := h.check(ctx); e != nil {
				return e
			}
		}
		if r.TrustRuntime() != stable {
			return ErrPinMismatch
		}
		return ctx.Err()
	}
	if e := check(); e != nil {
		return nil, e
	}
	rows, e := decodeEnrolledIndex(holds[len(holds)-1].body)
	if e != nil {
		return nil, e
	}
	var selected *enrolledSelection
	for i := range rows {
		s := &rows[i]
		if s.Subject.subject() == subject {
			selected = s
		}
	}
	if selected == nil || publisher.StatementCAS != selected.Evidence.StatementCAS || publisher.SignatureCAS != selected.Evidence.SignatureCAS || publisher.KeyFingerprint != selected.Evidence.KeyFingerprint {
		return nil, ErrPinMismatch
	}
	if e := check(); e != nil {
		return nil, e
	}
	resolution, e := stable.VerifySubject(ctx, subject, selected.Evidence.refs())
	if e != nil {
		return nil, e
	}
	if e := check(); e != nil {
		return nil, e
	}
	if !resolution.ValidFor(stable, binding) {
		return nil, ErrPinMismatch
	}
	return resolution, nil
}

// The fixed platform flags are the installed Go/x/sys ABI constants. Keeping
// them here avoids extending this two-file correction into platform helpers.
// Other OS/architectures refuse rather than falling back to a blocking open.
func enrolledOpenFlags(directory bool) (int, error) {
	var flags, dir int
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64", "darwin/amd64":
		flags, dir = 0x4|0x100|0x1000000, 0x100000 // NONBLOCK, NOFOLLOW, CLOEXEC; DIRECTORY
	case "linux/arm64":
		flags, dir = 0x800|0x8000|0x80000, 0x4000
	case "linux/amd64":
		flags, dir = 0x800|0x20000|0x80000, 0x10000
	default:
		return 0, ErrPinMismatch
	}
	if directory {
		flags |= dir
	}
	return os.O_RDONLY | flags, nil
}

// This acquisition is shared by the production lstat/open sequence and the
// deterministic substitution counter. No callback or observer grants authority.
func openEnrolledObserved(ctx context.Context, root *os.Root, name string, original os.FileInfo, directory bool) (*os.File, error) {
	if ctx == nil {
		return nil, ErrPinMismatch
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	flags, e := enrolledOpenFlags(directory)
	if e != nil {
		return nil, e
	}
	var f *os.File
	if root == nil {
		f, e = os.OpenFile(name, flags, 0)
	} else {
		f, e = root.OpenFile(name, flags, 0)
	}
	if e != nil {
		return nil, ErrPinMismatch
	}
	actual, e := f.Stat()
	good := e == nil
	if directory {
		good = good && enrolledParentSame(original, actual)
	} else {
		good = good && enrolledSingle(actual) && enrolledSame(original, actual)
	}
	if !good {
		_ = f.Close()
		return nil, ErrPinMismatch
	}
	if e = ctx.Err(); e != nil {
		_ = f.Close()
		return nil, e
	}
	return f, nil
}

// OpenRoot itself opens before verifying the directory type. Use only a fixed
// kernel descriptor alias of the already acquired directory, never its mutable
// source pathname. The resulting root is additionally checked against that FD.
func enrolledRootFromDirectory(file *os.File) (*os.Root, error) {
	if file == nil {
		return nil, ErrPinMismatch
	}
	info, e := file.Stat()
	if e != nil || !info.IsDir() {
		return nil, ErrPinMismatch
	}
	prefix := ""
	switch runtime.GOOS {
	case "darwin":
		prefix = "/dev/fd/"
	case "linux":
		prefix = "/proc/self/fd/"
	default:
		return nil, ErrPinMismatch
	}
	root, e := os.OpenRoot(prefix + strconv.FormatUint(uint64(file.Fd()), 10))
	if e != nil {
		return nil, ErrPinMismatch
	}
	actual, e := root.Stat(".")
	if e != nil || !enrolledParentSame(info, actual) {
		_ = root.Close()
		return nil, ErrPinMismatch
	}
	return root, nil
}
