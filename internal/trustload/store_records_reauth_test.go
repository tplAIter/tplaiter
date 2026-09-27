//go:build darwin || linux

package trustload

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

// TestStoreRecordsReauthSB09 covers the two record reauthentication surfaces:
// fixed external inputs are reloaded after a Store is opened, while persisted
// rows are read only through the exclusive root/binding capability.
func TestStoreRecordsReauthSB09(t *testing.T) {
	t.Run("external-pins", testStoreRecordsExternalPins)
	t.Run("accepted-records", testStoreRecordsAcceptedRows)
}

func testStoreRecordsExternalPins(t *testing.T) {
	cases := []struct {
		name string
		pin  func(*loadFixture) FilePin
	}{
		{"descriptor", func(f *loadFixture) FilePin { return f.install.Descriptor }},
		{"provisioning", func(f *loadFixture) FilePin { return f.install.Provisioning }},
		{"policy", func(f *loadFixture) FilePin { return f.install.ExecutionPolicy }},
		{"runtime-registration", func(f *loadFixture) FilePin {
			return FilePin{Path: f.installPath, SHA256: rawSHA256(mustRead(t, f.installPath))}
		}},
		{"operator-record", func(f *loadFixture) FilePin { return f.install.OperatorRecord }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
				t.Fatal(err)
			}
			store, err := OpenReadOnly(context.Background(), fixture.selection)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			pin := tc.pin(fixture.load)
			before := mustRead(t, pin.Path)
			mutated := append(append([]byte(nil), before...), '\n', ' ')
			if tc.name == "runtime-registration" {
				var object map[string]any
				if err := json.Unmarshal(before, &object); err != nil {
					t.Fatal(err)
				}
				object["installationID"] = "install.changed"
				mutated, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
			}
			if bytes.Equal(before, mutated) || json.Valid(before) && !json.Valid(mutated) {
				t.Fatal("mutation did not preserve the input syntax")
			}
			if err := os.WriteFile(pin.Path, mutated, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(context.Background()); err == nil {
				t.Fatal("Store.Load accepted changed fixed input")
			} else if !errors.Is(err, ErrProvenanceUnavailable) && !errors.Is(err, ErrPinMismatch) && !errors.Is(err, ErrConfigInvalid) {
				t.Fatal("Store.Load returned undeclared public error family")
			} else {
				assertSafeRecordErrorText(t, err)
			}
			external, err := bootstrap.LoadExternal(context.Background(), store)
			if err == nil || external != nil {
				t.Fatalf("LoadExternal accepted changed fixed input: context=%v err=%v", external, err)
			}
			assertSafeExternalRecordError(t, err)
		})
	}
}

type recordsMutation struct {
	name  string
	stage string
	want  error
	apply func(*sql.Conn) error
}

func testStoreRecordsAcceptedRows(t *testing.T) {
	cases := []recordsMutation{
		{"missing-installation", "open", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			_, err := c.ExecContext(context.Background(), `DELETE FROM installation WHERE singleton=1`)
			return err
		}},
	}
	for _, column := range []string{"installationID", "descriptorSHA256", "provisioningSHA256", "initialStateSHA256"} {
		column := column
		cases = append(cases, recordsMutation{"installation-" + column, "open", ErrPinMismatch, func(c *sql.Conn) error {
			value := "wrong"
			if column == "descriptorSHA256" || column == "provisioningSHA256" || column == "initialStateSHA256" {
				value = "sha256:" + strings.Repeat("f", 64)
			}
			_, err := c.ExecContext(context.Background(), `UPDATE installation SET `+column+`=? WHERE singleton=1`, value)
			return err
		}})
	}
	cases = append(cases,
		recordsMutation{"missing-accepted", "load", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			_, err := c.ExecContext(context.Background(), `DELETE FROM accepted WHERE singleton=1`)
			return err
		}},
		recordsMutation{"malformed-state", "load", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			_, err := c.ExecContext(context.Background(), `UPDATE accepted SET stateJSON=? WHERE singleton=1`, []byte(`{`))
			return err
		}},
		recordsMutation{"state-digest-wrong", "load", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			_, err := c.ExecContext(context.Background(), `UPDATE accepted SET stateSHA256=? WHERE singleton=1`, "sha256:"+strings.Repeat("e", 64))
			return err
		}},
		recordsMutation{"state-descriptor-wrong-self-hash", "load", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			return mutateAcceptedState(c, func(state *bootstrap.OSSAcceptedState) {
				state.DescriptorSHA256 = "sha256:" + strings.Repeat("d", 64)
				state.StateSHA256 = state.ComputedSHA256()
			})
		}},
		recordsMutation{"state-provisioning-wrong-self-hash", "load", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			return mutateAcceptedState(c, func(state *bootstrap.OSSAcceptedState) {
				state.ProvisioningSHA256 = "sha256:" + strings.Repeat("c", 64)
				state.StateSHA256 = state.ComputedSHA256()
			})
		}},
		recordsMutation{"malformed-bundle", "verify", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			_, err := c.ExecContext(context.Background(), `UPDATE accepted SET bundleJSON=? WHERE singleton=1`, []byte(`{`))
			return err
		}},
		recordsMutation{"missing-evidence-blob", "verify", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			var raw []byte
			if err := c.QueryRowContext(context.Background(), `SELECT bundleJSON FROM accepted WHERE singleton=1`).Scan(&raw); err != nil {
				return err
			}
			bundle, err := DecodeStoredBundle(raw)
			if err != nil {
				return err
			}
			_, err = c.ExecContext(context.Background(), `DELETE FROM blobs WHERE digest=?`, bundle.EnvelopeCAS)
			return err
		}},
		recordsMutation{"blob-bytes-wrong-digest", "verify", ErrProvenanceUnavailable, func(c *sql.Conn) error {
			var ref string
			if err := c.QueryRowContext(context.Background(), `SELECT digest FROM blobs ORDER BY digest LIMIT 1`).Scan(&ref); err != nil {
				return err
			}
			_, err := c.ExecContext(context.Background(), `UPDATE blobs SET bytes=? WHERE digest=?`, []byte("wrong-bytes"), ref)
			return err
		}},
	)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			if err := Enroll(context.Background(), fixture.selection, fixture.factory, fixture.stateJSON, fixture.bundleJSON, fixture.evidence); err != nil {
				t.Fatal(err)
			}
			mutateStoreRecords(t, fixture, tc.apply)
			store, err := OpenReadOnly(context.Background(), fixture.selection)
			if tc.stage == "open" {
				if err == nil || store != nil {
					if store != nil {
						store.Close()
					}
					t.Fatalf("OpenReadOnly accepted %s", tc.name)
				}
				assertSafeTypedRecordError(t, err, tc.want)
				return
			}
			if err != nil {
				t.Fatalf("OpenReadOnly rejected at wrong stage: %v", err)
			}
			defer store.Close()
			if tc.stage == "load" {
				if _, err := store.Load(context.Background()); err == nil {
					t.Fatalf("Store.Load accepted %s", tc.name)
				} else {
					assertSafeTypedRecordError(t, err, tc.want)
				}
				return
			}
			if _, err := store.Load(context.Background()); err != nil {
				t.Fatalf("Store.Load failed before VerifyOSS: %v", err)
			}
			if _, err := verifyCurrent(context.Background(), store, fixture.factory); err == nil {
				t.Fatalf("VerifyOSS accepted %s", tc.name)
			} else {
				assertSafeTypedRecordError(t, err, tc.want)
			}
		})
	}
}

func assertSafeTypedRecordError(t *testing.T, err, want error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("error=%v want typed %v", err, want)
	}
	assertSafeRecordErrorText(t, err)
}

func assertSafeRecordErrorText(t *testing.T, err error) {
	t.Helper()
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "sqlite") || strings.ContainsAny(text, "/\\") {
		t.Fatal("unsafe public error text")
	}
}

func assertSafeExternalRecordError(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, bootstrap.ErrExternalInvalid) {
		t.Fatalf("error=%v want typed %v", err, bootstrap.ErrExternalInvalid)
	}
	assertSafeRecordErrorText(t, err)
}

func mutateAcceptedState(c *sql.Conn, mutate func(*bootstrap.OSSAcceptedState)) error {
	var raw []byte
	if err := c.QueryRowContext(context.Background(), `SELECT stateJSON FROM accepted WHERE singleton=1`).Scan(&raw); err != nil {
		return err
	}
	state, err := bootstrap.DecodeOSSAcceptedState(raw)
	if err != nil {
		return err
	}
	mutate(state)
	changed, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = c.ExecContext(context.Background(), `UPDATE accepted SET stateJSON=?,stateSHA256=? WHERE singleton=1`, changed, state.StateSHA256)
	return err
}

func mutateStoreRecords(t *testing.T, fixture bootstrapFixture, mutate func(*sql.Conn) error) {
	t.Helper()
	lease, err := openRootLease(context.Background(), fixture.loaded.Install.OSS.StorePath, storeRefresh)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeRefresh)
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	if err := mutate(binding.conn); err != nil {
		binding.Close()
		lease.Close()
		t.Fatal(err)
	}
	if err := binding.Close(); err != nil {
		lease.Close()
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
