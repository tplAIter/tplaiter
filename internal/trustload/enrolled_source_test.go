package trustload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func enrolledTestRow() enrolledSelection {
	d := rawSHA256([]byte("neutral index transport"))
	return enrolledSelection{APIVersion: "tplaiter.dev/source-selection-input/v1", Subject: enrolledSubject{Origin: "https://example.test/tools", TemplatePath: ".", RequestedRef: strings.Repeat("a", 40), Commit: strings.Repeat("a", 40), TreeSHA256: d, ContractSHA256: d}, Evidence: enrolledEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: d, SignatureCAS: d, KeyFingerprint: d, CheckpointCAS: d, InclusionProofCAS: d}, Dependencies: []string{}}
}

func TestEnrolledIndexClosedCompleteTransport(t *testing.T) {
	row := enrolledTestRow()
	raw, e := canonicaljson.Canonical([]enrolledSelection{row})
	if e != nil {
		t.Fatal(e)
	}
	if rows, e := decodeEnrolledIndex(raw); e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	for name, bad := range map[string][]byte{
		"duplicate-row": append(append(append([]byte{}, raw[:len(raw)-1]...), ','), raw[1:]...),
		"duplicate-key": bytes.Replace(raw, []byte(`"dependencies":[]`), []byte(`"dependencies":[],"dependencies":[]`), 1),
		"unknown":       bytes.Replace(raw, []byte(`"dependencies":[]`), []byte(`"dependencies":[],"authority":true`), 1),
		"null":          bytes.Replace(raw, []byte(`"dependencies":[]`), []byte(`"dependencies":null`), 1),
		"missing":       bytes.Replace(raw, []byte(`"dependencies":[],`), nil, 1),
		"stale-format":  bytes.Replace(raw, []byte(bootstrap.PublisherStatementAPIVersion), []byte("future"), 1),
		"bad-proof":     bytes.Replace(raw, []byte(`"checkpointCAS":"`+row.Evidence.CheckpointCAS+`"`), []byte(`"checkpointCAS":"sha256:bad"`), 1),
		"empty":         []byte(`[]`), "overflow": make([]byte, enrolledIndexLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeEnrolledIndex(bad); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	rows := make([]enrolledSelection, 33)
	for i := range rows {
		rows[i] = row
	}
	bad, _ := json.Marshal(rows)
	if _, e := decodeEnrolledIndex(bad); e == nil {
		t.Fatal("truncated overflow")
	}
	row2 := row
	row2.Subject.Commit = strings.Repeat("b", 40)
	row2.Subject.RequestedRef = row2.Subject.Commit
	bad, _ = json.Marshal([]enrolledSelection{row, row2})
	if _, e := decodeEnrolledIndex(bad); e == nil {
		t.Fatal("accepted ambiguous source")
	}
}

func TestEnrolledObservationOriginalIdentityAndCleanup(t *testing.T) {
	// Physical /private/tmp avoids the platform's /var and /tmp symlink aliases.
	dir, e := os.MkdirTemp("/private/tmp", "u13-enrolled-observation-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "index.json")
	body := []byte(`[{"transport":"neutral"}]`)
	if e := os.WriteFile(path, body, 0o600); e != nil {
		t.Fatal(e)
	}
	hold, e := holdEnrolledFile(context.Background(), path, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer hold.close()
	if e := hold.check(context.Background()); e != nil {
		t.Fatal("original", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := hold.check(ctx); e == nil {
		t.Fatal("cancel")
	}
	if e := os.Rename(path, path+".old"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, body, 0o600); e != nil {
		t.Fatal(e)
	}
	if e := hold.check(context.Background()); e == nil {
		t.Fatal("equal body new inode accepted")
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(path+".old", path); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0o400); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0o600); e != nil {
		t.Fatal(e)
	}
	if e := hold.check(context.Background()); e == nil {
		t.Fatal("restored mode accepted")
	}
	if e := os.Link(path, path+".link"); e != nil {
		t.Fatal(e)
	}
	if _, e := holdEnrolledFile(context.Background(), path, 1024); e == nil {
		t.Fatal("hardlink admitted")
	}
	_ = os.Remove(path + ".link")
	if e := os.Symlink(path, path+".symlink"); e != nil {
		t.Fatal(e)
	}
	if _, e := holdEnrolledFile(context.Background(), path+".symlink", 1024); e == nil {
		t.Fatal("symlink admitted")
	}
	hold.close()
	if _, e := hold.file.Stat(); e == nil {
		t.Fatal("descriptor leaked")
	}
}

func TestEnrolledOpenTimeSubstitutionIsFinite(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("closed platform acquisition unsupported")
	}
	for _, directory := range []bool{false, true} {
		for _, replacement := range []string{"fifo", "symlink", "same-type-new-inode"} {
			t.Run(fmtEnrolledCase(directory, replacement), func(t *testing.T) {
				dir, e := filepath.EvalSymlinks(t.TempDir())
				if e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(dir, "observed")
				if directory {
					e = os.Mkdir(path, 0o700)
				} else {
					e = os.WriteFile(path, []byte("neutral original"), 0o600)
				}
				if e != nil {
					t.Fatal(e)
				}
				original, e := os.Lstat(path)
				if e != nil {
					t.Fatal(e)
				}
				// Precisely the review interleaving: retain the lstat observation, then
				// replace immediately before the exact production acquisition function.
				if e = os.Rename(path, path+".original"); e != nil {
					t.Fatal(e)
				}
				switch replacement {
				case "fifo":
					cctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					cmd := exec.CommandContext(cctx, "/usr/bin/mkfifo", path)
					cmd.Env = []string{"LANG=C"}
					if out, e := cmd.CombinedOutput(); e != nil {
						t.Fatalf("neutral fifo setup: %v %s", e, out)
					}
				case "symlink":
					e = os.Symlink(path+".original", path)
				default:
					if directory {
						e = os.Mkdir(path, 0o700)
					} else {
						e = os.WriteFile(path, []byte("neutral original"), 0o600)
					}
				}
				if e != nil {
					t.Fatal(e)
				}
				var root *os.Root
				name := path
				if !directory {
					root, e = os.OpenRoot(dir)
					if e != nil {
						t.Fatal(e)
					}
					defer root.Close()
					name = filepath.Base(path)
				}
				start := time.Now()
				f, e := openEnrolledObserved(context.Background(), root, name, original, directory)
				elapsed := time.Since(start)
				if f != nil {
					f.Close()
					t.Fatal("substituted object acquired")
				}
				if e == nil || elapsed > 250*time.Millisecond {
					t.Fatalf("finite refusal: error=%v elapsed=%v", e, elapsed)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				f, e = openEnrolledObserved(ctx, root, name, original, directory)
				if f != nil {
					f.Close()
					t.Fatal("canceled acquisition returned FD")
				}
				if !errors.Is(e, context.Canceled) {
					t.Fatalf("cancellation=%v", e)
				}
				t.Logf("actual substitution refusal %s %v; canceled acquisition returns context.Canceled", replacement, elapsed)
			})
		}
	}
}

func fmtEnrolledCase(directory bool, replacement string) string {
	if directory {
		return "parent/" + replacement
	}
	return "leaf/" + replacement
}

func TestEnrolledDescriptorRootAndOriginalHold(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "index.json")
	if e = os.WriteFile(path, []byte("neutral index"), 0o600); e != nil {
		t.Fatal(e)
	}
	observation, e := holdEnrolledFile(context.Background(), path, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer observation.close()
	if e = observation.check(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(path, path+".original"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("neutral index"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e = observation.check(context.Background()); e == nil {
		t.Fatal("equal-byte new inode admitted")
	}
}
