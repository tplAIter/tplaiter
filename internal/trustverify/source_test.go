package trustverify

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

type testReader struct {
	objects map[string]GitObject
	calls   int
}

func (r *testReader) ReadObject(_ context.Context, _ SourceOrigin, id ObjectID) (GitObject, error) {
	r.calls++
	o, ok := r.objects[string(id)]
	if !ok {
		return GitObject{}, errMissing{}
	}
	return GitObject{Kind: o.Kind, Data: append([]byte(nil), o.Data...)}, nil
}

type errMissing struct{}

func (errMissing) Error() string { return "missing" }
func refOID(w int, k string, d []byte) string {
	p := []byte(k + " " + itoa(len(d)) + "\x00")
	p = append(p, d...)
	if w == 20 {
		h := sha1.Sum(p)
		return hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(p)
	return hex.EncodeToString(h[:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 12)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
func refB(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func refD(d string, v any) string {
	var x any = v
	switch q := v.(type) {
	case refTree:
		a := make([]any, len(q.Entries))
		for i, e := range q.Entries {
			a[i] = map[string]any{"path": e.Path, "kind": e.Kind, "mode": e.Mode}
			if e.ContentSHA256 != "" {
				a[i].(map[string]any)["contentSHA256"] = e.ContentSHA256
			}
		}
		x = map[string]any{"apiVersion": q.APIVersion, "entries": a}
	case refContract:
		x = map[string]any{"apiVersion": q.APIVersion, "path": q.Path, "contentSHA256": q.ContentSHA256}
	}
	b, _ := json.Marshal(x)
	h := sha256.Sum256(append(append([]byte(d), 0), b...))
	return "sha256:" + hex.EncodeToString(h[:])
}

type refEntry struct {
	Path          string `json:"path"`
	Kind          string `json:"kind"`
	Mode          string `json:"mode"`
	ContentSHA256 string `json:"contentSHA256,omitempty"`
}
type refTree struct {
	APIVersion string     `json:"apiVersion"`
	Entries    []refEntry `json:"entries"`
}
type refContract struct {
	APIVersion    string `json:"apiVersion"`
	Path          string `json:"path"`
	ContentSHA256 string `json:"contentSHA256"`
}

func fixture(w int, c []byte) (*testReader, Subject) {
	r := &testReader{objects: map[string]GitObject{}}
	add := func(k string, d []byte) string { id := refOID(w, k, d); r.objects[id] = GitObject{k, d}; return id }
	empty := add("tree", nil)
	script := []byte("#!/bin/sh\necho ok\n")
	sid := add("blob", script)
	cid := add("blob", c)
	tree := []byte("40000 empty\x00")
	tree = append(tree, decodeHex(empty, w)...)
	tree = append(tree, []byte("100755 run.sh\x00")...)
	tree = append(tree, decodeHex(sid, w)...)
	tree = append(tree, []byte("100644 template.contract.json\x00")...)
	tree = append(tree, decodeHex(cid, w)...)
	rid := add("tree", tree)
	commit := []byte("tree " + rid + "\n\nauthor test <test@example.test> 0 +0000\n")
	mid := add("commit", commit)
	es := []refEntry{{"empty", "directory", "40000", ""}, {"run.sh", "file", "100755", refB(script)}, {"template.contract.json", "file", "100644", refB(c)}}
	td := refD("tplaiter.dev/source-content-tree/v1", refTree{"tplaiter.dev/source-content-tree/v1", es})
	cd := refD("tplaiter.dev/source-contract/v1", refContract{"tplaiter.dev/source-contract/v1", "template.contract.json", refB(c)})
	return r, Subject{"https://example.test/source", ".", mid, mid, td, cd}
}
func decodeHex(s string, w int) []byte { b, _ := hex.DecodeString(s); return b[:w] }
func TestVerifySourceSHA1AndSHA256NestedFixture(t *testing.T) {
	for _, w := range []int{20, 32} {
		t.Run(itoa(w), func(t *testing.T) {
			r, s := fixture(w, []byte("{\"apiVersion\":\"test\"}\n"))
			snap, e := VerifySource(context.Background(), r, s)
			if e != nil {
				t.Fatal(e)
			}
			if len(snap.Entries()) != 3 {
				t.Fatalf("entries=%d", len(snap.Entries()))
			}
			b, _ := snap.Blob("run.sh")
			b[0] = 'X'
			if got, _ := snap.Blob("run.sh"); got[0] == 'X' {
				t.Fatal("mutable blob")
			}
			c := snap.ContractBytes()
			c[0] = 'X'
			if snap.ContractBytes()[0] == 'X' {
				t.Fatal("mutable contract")
			}
		})
	}
}

func TestVerifySourceRawContractLineEndingsChangeDigest(t *testing.T) {
	r, s := fixture(20, []byte("{\"x\":1}\r\n"))
	if _, e := VerifySource(context.Background(), r, s); e != nil {
		t.Fatal(e)
	}
	_, s2 := fixture(20, []byte("{\"x\":1}\n"))
	if s.ContractSHA256 == s2.ContractSHA256 {
		t.Fatal("line endings unchanged")
	}
}

func TestVerifySourceFailuresLimitsCancel(t *testing.T) {
	r, s := fixture(20, []byte("{}"))
	bad := s
	bad.Commit = strings.Repeat("0", 40)
	bad.RequestedRef = bad.Commit
	if _, e := VerifySource(context.Background(), r, bad); e == nil {
		t.Fatal("wrong oid accepted")
	}
	rr := &testReader{objects: map[string]GitObject{}}
	for k, v := range r.objects {
		rr.objects[k] = v
	}
	for id, o := range rr.objects {
		if o.Kind == "blob" {
			o.Data = []byte("tamper")
			rr.objects[id] = o
			break
		}
	}
	if _, e := VerifySource(context.Background(), rr, s); e == nil {
		t.Fatal("tamper accepted")
	}
	lim := SourceLimits{MaxReads: 1, MaxEntries: 4096, MaxDepth: 64, MaxSourceBytes: 64 << 20}
	if _, e := VerifySourceWithLimits(context.Background(), r, s, lim); e == nil {
		t.Fatal("read limit accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := VerifySource(ctx, r, s); e == nil {
		t.Fatal("cancel accepted")
	}
}

func TestVerifyDevelopmentSourceAllowsMutableRequestedRefOnly(t *testing.T) {
	r, s := fixture(20, []byte("{\"apiVersion\":\"fixture\"}\n"))
	s.RequestedRef = "refs/heads/development"
	if _, err := VerifySource(context.Background(), r, s); err == nil {
		t.Fatal("stable mutable ref accepted")
	}
	if _, err := VerifyDevelopmentSource(context.Background(), r, s); err != nil {
		t.Fatalf("development pinned commit read: %v", err)
	}
}

func TestVerifySourceIndependentLiteralVectors(t *testing.T) {
	_, fixtureSubject := fixture(20, []byte("{\"apiVersion\":\"test\"}\n"))
	if fixtureSubject.TreeSHA256 != "sha256:e26600cf598c84ccf353e2756401f708a714474560401e6b3cb372949852429d" || fixtureSubject.ContractSHA256 != "sha256:1897cc2b08db835fadfe17c5096c26172207a0b4631ce593cc1b91e5f5dc0004" {
		t.Fatal("domain vector changed")
	}
	if got := refB([]byte("abc")); got != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal(got)
	}
	if got := refOID(20, "blob", nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatal(got)
	}
	if got := refOID(32, "blob", nil); got != "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813" {
		t.Fatal(got)
	}
}

func TestVerifySourceRejectsMalformedTreeModesNamesAndCommit(t *testing.T) {
	for _, w := range []int{20, 32} {
		t.Run(itoa(w), func(t *testing.T) {
			for _, tc := range []struct{ name, root, want string }{
				{"symlink", "120000 link\x00" + strings.Repeat("\x00", w), "unsupported tree mode"},
				{"submodule", "160000 module\x00" + strings.Repeat("\x00", w), "unsupported tree mode"},
				{"name", "100644 ../escape\x00" + strings.Repeat("\x00", w), "invalid tree name"},
				{"control", "100644 bad\x01name\x00" + strings.Repeat("\x00", w), "control in tree name"},
				{"order", "100644 z\x00" + strings.Repeat("\x00", w) + "100644 a\x00" + strings.Repeat("\x00", w), "noncanonical tree order"},
				{"truncated", "100644 file\x00" + strings.Repeat("\x00", w-1), "truncated tree oid"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r, s := parserFixture(w, []byte(tc.root), nil)
					if _, err := VerifySource(context.Background(), r, s); err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("err=%v", err)
					}
				})
			}
			r, s := parserFixture(w, nil, []byte("tree "+strings.Repeat("0", w*2)+"\ntree "+strings.Repeat("0", w*2)+"\n\n"))
			if _, err := VerifySource(context.Background(), r, s); err == nil || !strings.Contains(err.Error(), "duplicate tree header") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func parserFixture(w int, root, commit []byte) (*testReader, Subject) {
	r := &testReader{objects: map[string]GitObject{}}
	add := func(kind string, data []byte) string {
		id := refOID(w, kind, data)
		r.objects[id] = GitObject{kind, data}
		return id
	}
	rootID := add("tree", root)
	if commit == nil || len(commit) == 0 {
		commit = []byte("tree " + rootID + "\n\n")
	}
	commitID := add("commit", commit)
	return r, Subject{"https://example.test/source", ".", commitID, commitID, "sha256:tree", "sha256:contract"}
}

func nestedFixture(w int) (*testReader, Subject) {
	r := &testReader{objects: map[string]GitObject{}}
	add := func(kind string, data []byte) string {
		id := refOID(w, kind, data)
		r.objects[id] = GitObject{kind, data}
		return id
	}
	empty := add("tree", nil)
	script := []byte("#!/bin/sh\necho nested\n")
	contract := []byte("{\"apiVersion\":\"nested\"}\n")
	sid, cid := add("blob", script), add("blob", contract)
	selected := treeBytes(w, []testTree{{"40000", "empty", empty}, {"100755", "run.sh", sid}, {"100644", "template.contract.json", cid}})
	selectedID := add("tree", selected)
	nested := add("tree", treeBytes(w, []testTree{{"40000", "nested", selectedID}}))
	root := add("tree", treeBytes(w, []testTree{{"40000", "templates", nested}}))
	commit := add("commit", []byte("tree "+root+"\n\n"))
	entries := []refEntry{{"empty", "directory", "40000", ""}, {"run.sh", "file", "100755", refB(script)}, {"template.contract.json", "file", "100644", refB(contract)}}
	return r, Subject{"https://example.test/source", "templates/nested", commit, commit, refD("tplaiter.dev/source-content-tree/v1", refTree{"tplaiter.dev/source-content-tree/v1", entries}), refD("tplaiter.dev/source-contract/v1", refContract{"tplaiter.dev/source-contract/v1", "template.contract.json", refB(contract)})}
}

type testTree struct{ mode, name, oid string }

func treeBytes(w int, records []testTree) []byte {
	var out []byte
	for _, r := range records {
		out = append(out, []byte(r.mode+" "+r.name+"\x00")...)
		out = append(out, decodeHex(r.oid, w)...)
	}
	return out
}

func TestVerifySourceNestedSelectionBothWidthsAndLiteralVectors(t *testing.T) {
	for _, w := range []int{20, 32} {
		t.Run(itoa(w), func(t *testing.T) {
			r, s := nestedFixture(w)
			snap, err := VerifySource(context.Background(), r, s)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(snap.Entries()); got != 3 {
				t.Fatalf("entries=%d", got)
			}
			if _, ok := snap.Blob("template.contract.json"); !ok {
				t.Fatal("nested contract missing")
			}
			t.Logf("tree=%s contract=%s", s.TreeSHA256, s.ContractSHA256)
			if s.TreeSHA256 != "sha256:096cecdfcf8917e7823d8ba74096999e0aeb2f592e3092429861662666cc4220" || s.ContractSHA256 != "sha256:a72bb9a7020d10246ccf86109ec2300a61278a757f30dea284a92198df643505" {
				t.Fatalf("unexpected literal vectors: %#v", s)
			}
		})
	}
}

func TestVerifySourceTemplatePathValidationBeforeRead(t *testing.T) {
	r, s := fixture(20, []byte("{}"))
	for _, path := range []string{"../x", "x/../y", "x//y", "/x", "x/", "x\\y", "x/./y", "x/\x01y"} {
		t.Run(path, func(t *testing.T) {
			bad := s
			bad.TemplatePath = path
			before := r.calls
			if _, err := VerifySource(context.Background(), r, bad); err == nil || !strings.Contains(err.Error(), "invalid path") {
				t.Fatalf("err=%v", err)
			}
			if r.calls != before {
				t.Fatal("invalid path reached reader")
			}
		})
	}
}

func TestVerifySourceLimitsReachTargetBranches(t *testing.T) {
	t.Run("contract-before-copy", func(t *testing.T) {
		r, s := oversizedBlobFixture(20, "template.contract.json", maxContractObject+1)
		if _, err := VerifySource(context.Background(), r, s); err == nil || !strings.Contains(err.Error(), "contract size") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("blob", func(t *testing.T) {
		r, s := oversizedBlobFixture(20, "large", maxBlobObject+1)
		if _, err := VerifySource(context.Background(), r, s); err == nil || !strings.Contains(err.Error(), "object size") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("source-bytes", func(t *testing.T) {
		r, s := fixture(20, []byte("{}"))
		if _, err := VerifySourceWithLimits(context.Background(), r, s, SourceLimits{MaxReads: 20, MaxEntries: 20, MaxDepth: 20, MaxSourceBytes: 1}); err == nil || !strings.Contains(err.Error(), "source size") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("entries", func(t *testing.T) {
		r, s := fixture(20, []byte("{}"))
		if _, err := VerifySourceWithLimits(context.Background(), r, s, SourceLimits{MaxReads: 20, MaxEntries: 1, MaxDepth: 20, MaxSourceBytes: 100}); err == nil || !strings.Contains(err.Error(), "entry limit") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		r, s := nestedFixture(20)
		if _, err := VerifySourceWithLimits(context.Background(), r, s, SourceLimits{MaxReads: 20, MaxEntries: 20, MaxDepth: 1, MaxSourceBytes: 100}); err == nil || !strings.Contains(err.Error(), "depth limit") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("path-bytes-and-runes", func(t *testing.T) {
		r, s := fixture(20, []byte("{}"))
		before := r.calls
		for _, path := range []string{strings.Repeat("a", maxPathBytes+1), strings.Repeat("界", maxPathRunes+1)} {
			bad := s
			bad.TemplatePath = path
			if _, err := VerifySource(context.Background(), r, bad); err == nil {
				t.Fatal("path limit accepted")
			}
		}
		if r.calls != before {
			t.Fatal("path limit reached reader")
		}
	})
}

func oversizedBlobFixture(w int, name string, size int) (*testReader, Subject) {
	r := &testReader{objects: map[string]GitObject{}}
	add := func(kind string, data []byte) string {
		id := refOID(w, kind, data)
		r.objects[id] = GitObject{kind, data}
		return id
	}
	large := add("blob", make([]byte, size))
	contract := add("blob", []byte("{}"))
	records := []testTree{{"100644", "template.contract.json", contract}}
	if name == "template.contract.json" {
		records[0].oid = large
	} else {
		records = append([]testTree{{"100644", name, large}}, records...)
	}
	root := add("tree", treeBytes(w, records))
	commit := add("commit", []byte("tree "+root+"\n\n"))
	return r, Subject{"https://example.test/source", ".", commit, commit, "sha256:x", "sha256:y"}
}

func TestVerifySourceRepeatedReadBudgetAndCancelAfterReaderReturn(t *testing.T) {
	r, s := repeatedBlobFixture(20)
	if _, err := VerifySourceWithLimits(context.Background(), r, s, SourceLimits{MaxReads: 3, MaxEntries: 20, MaxDepth: 20, MaxSourceBytes: 100}); err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("err=%v", err)
	}
	r, s = repeatedBlobFixture(20)
	if _, err := VerifySourceWithLimits(context.Background(), r, s, SourceLimits{MaxReads: 20, MaxEntries: 20, MaxDepth: 20, MaxSourceBytes: 3}); err == nil || !strings.Contains(err.Error(), "source size") {
		t.Fatalf("err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr := cancelAfterReader{testReader: *r, cancel: cancel}
	if _, err := VerifySource(ctx, &cr, s); err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("err=%v", err)
	}
}

type cancelAfterReader struct {
	testReader
	cancel context.CancelFunc
}

func (r *cancelAfterReader) ReadObject(ctx context.Context, origin SourceOrigin, id ObjectID) (GitObject, error) {
	o, err := r.testReader.ReadObject(ctx, origin, id)
	r.cancel()
	return o, err
}

func repeatedBlobFixture(w int) (*testReader, Subject) {
	r := &testReader{objects: map[string]GitObject{}}
	add := func(kind string, data []byte) string {
		id := refOID(w, kind, data)
		r.objects[id] = GitObject{kind, data}
		return id
	}
	shared := add("blob", []byte("{}"))
	root := add("tree", treeBytes(w, []testTree{{"100644", "copy", shared}, {"100644", "template.contract.json", shared}}))
	commit := add("commit", []byte("tree "+root+"\n\n"))
	return r, Subject{"https://example.test/source", ".", commit, commit, "sha256:x", "sha256:y"}
}
