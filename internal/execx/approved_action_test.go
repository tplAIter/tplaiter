package execx

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
)

// Actual filesystem mechanisms below use no runtime or signed approval.
func TestActionStageOriginalIdentityAndCleanup(t *testing.T) {
	for _, mutation := range []string{"none", "new-inode", "restored-mode", "grow", "hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			root, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			s, e := newActionStage(root, actionLaunch{descriptor: []byte("{}"), projection: operationtrust.ActionProjection{Files: []operationtrust.ActionInputFile{}}})
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(s.path, "descriptors")
			switch mutation {
			case "new-inode":
				if e = os.Remove(path); e == nil {
					e = os.WriteFile(path, []byte("{}"), 0o400)
				}
			case "restored-mode":
				if e = os.Chmod(path, 0o600); e == nil {
					e = os.Chmod(path, 0o400)
				}
			case "grow":
				if e = os.Chmod(path, 0o600); e == nil {
					e = os.WriteFile(path, []byte("larger"), 0o600)
				}
				if e == nil {
					e = os.Chmod(path, 0o400)
				}
			case "hardlink":
				e = os.Link(path, filepath.Join(root, "extra-link"))
			}
			if e != nil {
				t.Fatal(e)
			}
			e = s.check()
			if (e == nil) != (mutation == "none") {
				t.Fatalf("mutation %s: check %v", mutation, e)
			}
			e = s.close()
			if mutation == "new-inode" {
				if e == nil {
					t.Fatal("foreign replacement cleanup accepted")
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, []byte("{}")) {
					t.Fatal("foreign replacement removed")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = os.Lstat(s.path); !os.IsNotExist(e) {
				t.Fatalf("stage remains: %v", e)
			}
			if e = s.close(); e != nil {
				t.Fatal("repeat cleanup", e)
			}
		})
	}
}

func TestActionBoundedOutputPreservesPrefixFacts(t *testing.T) {
	signal := make(chan struct{}, 1)
	b := &actionBuffer{limit: 8, signal: signal}
	if n, e := b.Write([]byte("abcdefghijk")); n != 11 || e != nil {
		t.Fatal(n, e)
	}
	got, overflow := b.result()
	if !overflow || !bytes.Equal(got, []byte("abcdefgh")) {
		t.Fatal("lost bounded prefix")
	}
	select {
	case <-signal:
	default:
		t.Fatal("missing overflow cancellation")
	}
	if e := ValidateActionProcessResult(ActionProcessResult{APIVersion: "tplaiter.dev/action-receipt/v1", Launched: "yes", Stdout: got, StdoutSHA256: evidencecas.Digest(got)}); e == nil {
		t.Fatal("incomplete factual body accepted")
	}
}

func TestActionStdinStageRetainsOffsetAndIdentity(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	want := []byte("selected authenticated stdin\n")
	s, e := newActionStage(root, actionLaunch{descriptor: []byte("{}"), projection: operationtrust.ActionProjection{Stdin: want}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	f := s.files[len(s.files)-1]
	b := make([]byte, len(want))
	n, e := f.ReadAt(b, 0)
	if e != nil || n != len(want) || !bytes.Equal(b, want) {
		t.Fatal("stdin projection mismatch")
	}
	offset, e := f.Seek(0, 1)
	if e != nil || offset != 0 {
		t.Fatal("pread consumed stdin")
	}
	if e = s.check(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(s.path, "stdin")
	if e = os.Chmod(path, 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0o400); e != nil {
		t.Fatal(e)
	}
	if e = s.check(); e == nil {
		t.Fatal("restored-mode stdin mutation accepted")
	}
}
