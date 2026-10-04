package sourcepackage

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func fixture(t *testing.T, bare bool) (CaptureInput, map[string]string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := root
	if !bare {
		dir = filepath.Join(root, ".git")
	}
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[core]\nrepositoryformatversion = 0\nbare = true\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "refs", "heads"), 0o700); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(data))), data...)
		hash := sha1.Sum(raw)
		id := hex.EncodeToString(hash[:])
		p := filepath.Join(dir, "objects", id[:2], id[2:])
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		z := zlib.NewWriter(f)
		if _, err = z.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		return id
	}
	files := map[string][]byte{"template.contract.json": []byte("{}"), "template.manifest.yaml": []byte("native manifest\n"), "hello": []byte("immutable\n")}
	names := []string{}
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var tree []byte
	for _, name := range names {
		id := add("blob", files[name])
		ids[name] = id
		bin, _ := hex.DecodeString(id)
		tree = append(tree, []byte("100644 "+name+"\x00")...)
		tree = append(tree, bin...)
	}
	subtree := add("tree", tree)
	ids["subtree"] = subtree
	sibling := add("blob", []byte("excluded"))
	ids["sibling"] = sibling
	b1, _ := hex.DecodeString(subtree)
	b2, _ := hex.DecodeString(sibling)
	rootTree := append([]byte("40000 selected\x00"), b1...)
	rootTree = append(rootTree, []byte("100644 sibling\x00")...)
	rootTree = append(rootTree, b2...)
	tid := add("tree", rootTree)
	ids["root"] = tid
	parent := add("commit", []byte("tree "+tid+"\n\nparent\n"))
	ids["parent"] = parent
	commit := add("commit", []byte("tree "+tid+"\nparent "+parent+"\n\nfixture\n"))
	ids["commit"] = commit
	if err := os.WriteFile(filepath.Join(dir, "refs", "heads", "main"), []byte(commit+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return CaptureInput{RepositoryPath: root, Origin: "https://example.test/offline", TemplatePath: "selected", Commit: commit}, ids
}

type publicReader struct{ objects map[string][]byte }

func (r publicReader) ReadObject(_ context.Context, _ trustverify.SourceOrigin, id trustverify.ObjectID) (trustverify.GitObject, error) {
	raw, ok := r.objects[string(id)]
	if !ok {
		return trustverify.GitObject{}, errors.New("missing")
	}
	z := bytes.IndexByte(raw, 0)
	return trustverify.GitObject{Kind: strings.Split(string(raw[:z]), " ")[0], Data: raw[z+1:]}, nil
}

func TestCaptureOrdinaryBareAndPackedExactClosure(t *testing.T) {
	for _, kind := range []string{"ordinary", "bare", "packed"} {
		t.Run(kind, func(t *testing.T) {
			input, ids := fixture(t, kind != "ordinary")
			if kind == "packed" {
				cmd := exec.Command("/usr/bin/git", "--git-dir="+input.RepositoryPath, "-c", "repack.writeBitmaps=false", "repack", "-ad")
				cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
				if _, err := cmd.Output(); err != nil {
					t.Fatal("test repack failed")
				}
			}
			t.Setenv("GIT_OBJECT_DIRECTORY", "/unusable")
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "include.path")
			t.Setenv("GIT_CONFIG_VALUE_0", "/unusable")
			captured, err := Capture(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if len(captured.Objects) != 6 || captured.Objects[ids["sibling"]] != nil || captured.Objects[ids["parent"]] != nil {
				t.Fatal("capture did not preserve exact selected closure")
			}
			if _, err := trustverify.VerifySource(context.Background(), publicReader{captured.Objects}, captured.Subject); err != nil {
				t.Fatal(err)
			}
			wrong := captured.Subject
			wrong.TreeSHA256 = "sha256:" + strings.Repeat("0", 64)
			if _, err := trustverify.VerifySource(context.Background(), publicReader{captured.Objects}, wrong); err == nil {
				t.Fatal("capture bypassed digest verification")
			}
		})
	}
}

func TestCaptureRefusesUnsafeLayoutsAndObjects(t *testing.T) {
	for _, kind := range []string{"include", "includeif", "extensions", "worktree", "alternates", "http-alternates", "shallow", "replace", "commondir", "gitfile", "gitlink", "symlink-object", "corrupt", "wrong-hash", "missing", "oversize", "promisor", "aux-pack", "symlink-parent"} {
		t.Run(kind, func(t *testing.T) {
			input, ids := fixture(t, false)
			dir := filepath.Join(input.RepositoryPath, ".git")
			write := func(path string, raw []byte) {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "include", "includeif", "extensions":
				write(filepath.Join(dir, "config"), []byte("[core]\nrepositoryformatversion=0\n["+kind+"]\npath=/unread-secret\n"))
			case "worktree":
				write(filepath.Join(dir, "config"), []byte("[core]\nrepositoryformatversion=0\nworktree=/unread-secret\n"))
			case "alternates", "http-alternates":
				write(filepath.Join(dir, "objects", "info", kind), nil)
			case "shallow", "commondir":
				write(filepath.Join(dir, kind), nil)
			case "replace":
				if err := os.Mkdir(filepath.Join(dir, "refs", "replace"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "gitfile":
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				write(dir, []byte("gitdir: /unread-secret"))
			case "gitlink":
				if err := os.Rename(dir, dir+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-real", dir); err != nil {
					t.Fatal(err)
				}
			case "symlink-object":
				p := filepath.Join(dir, "objects", ids["commit"][:2], ids["commit"][2:])
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/unread-secret", p); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				write(filepath.Join(dir, "objects", ids["commit"][:2], ids["commit"][2:]), []byte("corrupt"))
			case "wrong-hash":
				var compressed bytes.Buffer
				z := zlib.NewWriter(&compressed)
				_, _ = z.Write([]byte("commit 5\x00wrong"))
				if err := z.Close(); err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(dir, "objects", ids["commit"][:2], ids["commit"][2:]), compressed.Bytes())
			case "missing":
				if err := os.Remove(filepath.Join(dir, "objects", ids["commit"][:2], ids["commit"][2:])); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				p := filepath.Join(dir, "objects", ids["commit"][:2], ids["commit"][2:])
				if err := os.Truncate(p, maxContainerBytes+1); err != nil {
					t.Fatal(err)
				}
			case "promisor", "aux-pack":
				write(filepath.Join(dir, "objects", "pack", "pack-"+strings.Repeat("a", 40)+"."+kind), nil)
			case "symlink-parent":
				alias := input.RepositoryPath + "-alias"
				if err := os.Symlink(input.RepositoryPath, alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(alias) })
				input.RepositoryPath = alias
			}
			if _, err := Capture(context.Background(), input); err == nil {
				t.Fatal("unsafe capture accepted")
			}
		})
	}
}

func TestBatchHeaderBoundsBeforeAllocation(t *testing.T) {
	id := strings.Repeat("a", 40)
	for _, s := range []string{id + " blob 16777217\n", id + " tree 1048577\n", id + " blob 18446744073709551616\n", id + " blob 01\n", id + " tag 1\n", id + " missing\n", strings.Repeat("x", 129) + "\n", strings.Repeat("b", 40) + " blob 1\n", id + " blob 1"} {
		if _, _, err := batchHeader(bufio.NewReader(strings.NewReader(s)), id, maxRawBytes); err == nil {
			t.Fatal("invalid batch header accepted")
		}
	}
	if _, _, err := batchHeader(bufio.NewReader(strings.NewReader(id+" blob 10\n")), id, 10); err == nil {
		t.Fatal("aggregate frame budget ignored")
	}
}

func TestCaptureCancellationAndMutableRef(t *testing.T) {
	input, _ := fixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Capture(ctx, input); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	input.Commit = "main"
	if _, err := Capture(context.Background(), input); err == nil {
		t.Fatal("mutable ref accepted")
	}
}

func TestCapturePublicGoD017(t *testing.T) {
	path := "/private/tmp/tplaiter-template-go-20261004"
	if _, err := os.Stat(path); err != nil {
		t.Skip("public Go checkout unavailable")
	}
	input := CaptureInput{RepositoryPath: path, Origin: "https://github.com/tplAIter/template-go", TemplatePath: ".", Commit: "d0179547cd2e47b7564b0011bc5045799fc036bd"}
	captured, err := Capture(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := trustverify.VerifySource(context.Background(), publicReader{captured.Objects}, captured.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.Blob("template.manifest.yaml"); !ok {
		t.Fatal("real native manifest absent")
	}
	if _, ok := snapshot.Blob("generators/entity/entity.go.tmpl"); !ok && len(snapshot.Entries()) < 10 {
		t.Fatal("real Go closure unexpectedly small")
	}
}
