// Package migrations builds a deterministic, side-effect-free template
// migration plan and the byte image of the project's migrations ledger.
//
// It does not execute anything and does not decide who may execute: a plan
// that selects executable steps is returned only after the caller-supplied
// Authorize callback (the trust runtime's execution permit, see
// internal/operationtrust) approved them.
package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// LedgerRelPath is the project-relative applied-migrations ledger.
const LedgerRelPath = naming.ProjectDir + "/migrations.json"

// LedgerVersion is the only supported ledger format version.
const LedgerVersion = 1

// ErrExecutionUnauthorized reports that selected migrations run template code
// and no execution authority approved them.
var ErrExecutionUnauthorized = errors.New("migrations: executable migrations are not authorized")

var settingsKeyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// Ledger is the applied-migrations ledger.
type Ledger struct {
	Version int           `json:"version"`
	Applied []LedgerEntry `json:"applied"`
}

// LedgerEntry records one applied migration by ID, digest and order.
type LedgerEntry struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Order  int    `json:"order"`
}

// PlannedMigration is one selected migration.
type PlannedMigration struct {
	ID       string            `json:"id"`
	Digest   string            `json:"digest"`
	Order    int               `json:"order"`
	Phase    string            `json:"phase"`
	Steps    []MigrationStep   `json:"steps"`
	Settings MigrationSettings `json:"settings,omitempty"`
}

// LedgerMutation is an intended byte-level mutation. The caller can put it in
// a transaction journal before executing the plan; Build never writes it.
type LedgerMutation struct {
	Path   string `json:"path"`
	Before []byte `json:"before"`
	After  []byte `json:"after"`
}

// Plan is the selected migrations, split by phase, plus the ledger image.
type Plan struct {
	Before []PlannedMigration `json:"before"`
	After  []PlannedMigration `json:"after"`
	Ledger LedgerMutation     `json:"ledger"`
	// Unversioned is set when the current or target selector is not a
	// release version (a branch or "latest"). No migration is selected.
	Unversioned bool   `json:"unversioned,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Options are the inputs of Build.
type Options struct {
	// CurrentVersion and TargetVersion are release versions ("1.2.0",
	// "v1.2.0" or "refs/tags/v1.2.0"). Anything else yields an unversioned
	// plan.
	CurrentVersion string
	TargetVersion  string
	// LedgerBytes are the exact current ledger bytes; nil means absent.
	LedgerBytes []byte
	// Authorize approves the selected executable migrations. It is required
	// only when at least one selected migration has steps; settings-only
	// migrations are pure data transformations.
	Authorize func([]PlannedMigration) error
}

// ParseVersion parses a release selector. A leading "refs/tags/" is ignored.
func ParseVersion(selector string) (*semver.Version, error) {
	v, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(selector), "refs/tags/"))
	if err != nil {
		return nil, fmt.Errorf("migrations: %q is not a release version: %w", selector, err)
	}
	return v, nil
}

// Build verifies the immutable ledger and selects every manifest boundary in
// (current, target]. It is deliberately pure: executable input is authorized
// before a Plan (and therefore before any journal-ready mutation) is returned.
func Build(migrations []Migration, opts Options) (*Plan, error) {
	current, currentErr := ParseVersion(opts.CurrentVersion)
	target, targetErr := ParseVersion(opts.TargetVersion)
	if currentErr == nil && targetErr == nil && !target.GreaterThan(current) {
		return nil, errors.New("migrations: target version must be greater than current")
	}

	ledger, err := parseLedger(opts.LedgerBytes)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]LedgerEntry, len(ledger.Applied))
	for _, entry := range ledger.Applied {
		byID[entry.ID] = entry
	}

	canonical := make([]PlannedMigration, len(migrations))
	seenIDs := make(map[string]struct{}, len(migrations))
	var previousBoundary *semver.Version
	for i, migration := range migrations {
		if err := validateMigration(migration); err != nil {
			return nil, fmt.Errorf("migrations: migration %d: %w", i, err)
		}
		if _, exists := seenIDs[migration.ID]; exists {
			return nil, fmt.Errorf("migrations: duplicate migration id %q", migration.ID)
		}
		seenIDs[migration.ID] = struct{}{}
		boundary, _ := semver.StrictNewVersion(migration.To)
		if previousBoundary != nil && boundary.LessThan(previousBoundary) {
			return nil, fmt.Errorf("migrations: migration %d boundary %s is lower than previous boundary %s", i, boundary, previousBoundary)
		}
		previousBoundary = boundary

		digest, err := migrationDigest(migration)
		if err != nil {
			return nil, err
		}
		canonical[i] = PlannedMigration{
			ID:       migration.ID,
			Digest:   digest,
			Order:    i,
			Phase:    migration.Phase,
			Steps:    append([]MigrationStep(nil), migration.Steps...),
			Settings: cloneSettings(migration.Settings),
		}
		if applied, ok := byID[migration.ID]; ok && (applied.Digest != digest || applied.Order != i) {
			return nil, fmt.Errorf("migrations: applied migration %q changed or reordered", migration.ID)
		}
	}
	for _, applied := range ledger.Applied {
		if applied.Order >= len(canonical) || canonical[applied.Order].ID != applied.ID {
			return nil, fmt.Errorf("migrations: applied migration %q missing or reordered", applied.ID)
		}
	}

	// A branch or moving selector (for example an @latest lock on "main") has
	// no version to order migrations against. The ledger and the declared
	// migrations are still verified above, but nothing is selected: such a
	// project is unversioned until it is pinned to a release.
	if currentErr != nil || targetErr != nil {
		var reason string
		if currentErr != nil {
			reason = fmt.Sprintf("current version %q is not a release version", opts.CurrentVersion)
		} else {
			reason = fmt.Sprintf("target version %q is not a release version", opts.TargetVersion)
		}
		return &Plan{Unversioned: true, Reason: reason, Ledger: LedgerMutation{Path: LedgerRelPath, Before: clone(opts.LedgerBytes), After: clone(opts.LedgerBytes)}}, nil
	}

	plan := &Plan{}
	selected := make([]int, 0)
	lastAppliedOrder := -1
	if len(ledger.Applied) > 0 {
		lastAppliedOrder = ledger.Applied[len(ledger.Applied)-1].Order
	}
	for i, migration := range migrations {
		if _, applied := byID[migration.ID]; applied {
			continue
		}
		to, _ := semver.NewVersion(migration.To) // validated above
		if current.LessThan(to) && !target.LessThan(to) {
			if i <= lastAppliedOrder {
				return nil, fmt.Errorf("migrations: unapplied migration %q precedes an applied migration", migration.ID)
			}
			selected = append(selected, i)
			if migration.Phase == "before" {
				plan.Before = append(plan.Before, canonical[i])
			} else {
				plan.After = append(plan.After, canonical[i])
			}
		}
	}
	if len(selected) > 0 {
		var executable []PlannedMigration
		for _, i := range selected {
			if migrations[i].Executable() {
				executable = append(executable, canonical[i])
			}
		}
		if len(executable) > 0 {
			if opts.Authorize == nil {
				return nil, fmt.Errorf("%w: no execution authority was supplied", ErrExecutionUnauthorized)
			}
			if err := opts.Authorize(executable); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrExecutionUnauthorized, err)
			}
		}
	} else {
		plan.Ledger = LedgerMutation{
			Path:   LedgerRelPath,
			Before: clone(opts.LedgerBytes),
			After:  clone(opts.LedgerBytes),
		}
		return plan, nil
	}
	for _, i := range selected {
		ledger.Applied = append(ledger.Applied, LedgerEntry{
			ID:     canonical[i].ID,
			Digest: canonical[i].Digest,
			Order:  i,
		})
	}

	after, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("migrations: encode ledger: %w", err)
	}
	after = append(after, '\n')
	plan.Ledger = LedgerMutation{
		Path:   LedgerRelPath,
		Before: clone(opts.LedgerBytes),
		After:  after,
	}
	return plan, nil
}

func validateMigration(migration Migration) error {
	if strings.TrimSpace(migration.ID) == "" {
		return errors.New("id is required")
	}
	from, err := semver.StrictNewVersion(migration.From)
	if err != nil {
		return fmt.Errorf("from: %w", err)
	}
	to, err := semver.StrictNewVersion(migration.To)
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}
	if !to.GreaterThan(from) {
		return errors.New("to must be greater than from")
	}
	if migration.Phase != "before" && migration.Phase != "after" {
		return errors.New("phase must be before or after")
	}
	if len(migration.Steps) == 0 && len(migration.Settings.Rename) == 0 && len(migration.Settings.Delete) == 0 {
		return errors.New("at least one executable or settings step is required")
	}
	for i, step := range migration.Steps {
		run := strings.TrimSpace(step.Run)
		ansible := strings.TrimSpace(step.Ansible)
		if (run == "") == (ansible == "") {
			return fmt.Errorf("step %d: exactly one of run or ansible is required", i)
		}
		clean := path.Clean(ansible)
		if ansible != "" && (path.IsAbs(ansible) || clean != ansible || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(ansible, "\\")) {
			return fmt.Errorf("step %d: ansible must be a safe relative path", i)
		}
	}
	if err := validateSettingsMigration(migration.Settings); err != nil {
		return err
	}
	return nil
}

func validateSettingsMigration(migration MigrationSettings) error {
	deleted := map[string]struct{}{}
	for _, key := range migration.Delete {
		if !settingsKeyRE.MatchString(key) {
			return fmt.Errorf("invalid settings delete key %q", key)
		}
		if _, exists := deleted[key]; exists {
			return fmt.Errorf("duplicate settings delete key %q", key)
		}
		deleted[key] = struct{}{}
	}
	targets := map[string]string{}
	for from, to := range migration.Rename {
		if !settingsKeyRE.MatchString(from) || !settingsKeyRE.MatchString(to) || from == to {
			return fmt.Errorf("invalid settings rename %q to %q", from, to)
		}
		if _, exists := deleted[from]; exists {
			return fmt.Errorf("settings key %q cannot be renamed and deleted", from)
		}
		if previous, exists := targets[to]; exists && previous != from {
			return fmt.Errorf("settings keys %q and %q both rename to %q", previous, from, to)
		}
		targets[to] = from
	}
	return nil
}

// ApplySettings applies selected transformations in authored migration order.
// Renames within one migration are simultaneous, making chains independent of
// Go map iteration order. The input map is never mutated.
func ApplySettings(plan *Plan, input map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	if plan == nil {
		return out, nil
	}
	selected := append([]PlannedMigration(nil), plan.Before...)
	selected = append(selected, plan.After...)
	sort.Slice(selected, func(i, j int) bool { return selected[i].Order < selected[j].Order })
	for _, migration := range selected {
		if err := applySettingsStep(out, migration.Settings); err != nil {
			return nil, fmt.Errorf("migrations: apply settings for %q: %w", migration.ID, err)
		}
	}
	return out, nil
}

func applySettingsStep(values map[string]any, step MigrationSettings) error {
	sources := make([]string, 0, len(step.Rename))
	for source := range step.Rename {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	moved := make(map[string]any, len(sources))
	sourceSet := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		sourceSet[source] = struct{}{}
		if value, exists := values[source]; exists {
			moved[source] = value
		}
	}
	for _, source := range sources {
		target := step.Rename[source]
		if _, sourceWillMove := sourceSet[target]; !sourceWillMove {
			if _, targetExists := values[target]; targetExists {
				return fmt.Errorf("rename target %q already exists", target)
			}
		}
		delete(values, source)
	}
	for _, source := range sources {
		if value, exists := moved[source]; exists {
			values[step.Rename[source]] = value
		}
	}
	for _, key := range step.Delete {
		delete(values, key)
	}
	return nil
}

func parseLedger(data []byte) (Ledger, error) {
	if len(data) == 0 {
		return Ledger{Version: LedgerVersion, Applied: []LedgerEntry{}}, nil
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Ledger{}, fmt.Errorf("migrations: parse ledger: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire struct {
		Version int            `json:"version"`
		Applied *[]LedgerEntry `json:"applied"`
	}
	if err := decoder.Decode(&wire); err != nil {
		return Ledger{}, fmt.Errorf("migrations: parse ledger: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Ledger{}, fmt.Errorf("migrations: parse ledger: %w", err)
	}
	if wire.Applied == nil {
		return Ledger{}, errors.New("migrations: ledger applied must be present and non-null")
	}
	ledger := Ledger{Version: wire.Version, Applied: *wire.Applied}
	if ledger.Version != LedgerVersion {
		return Ledger{}, fmt.Errorf("migrations: unsupported ledger version %d", ledger.Version)
	}
	seenIDs := map[string]struct{}{}
	seenOrders := map[int]struct{}{}
	previousOrder := -1
	for _, entry := range ledger.Applied {
		if strings.TrimSpace(entry.ID) == "" {
			return Ledger{}, errors.New("migrations: ledger entry id is required")
		}
		if _, ok := seenIDs[entry.ID]; ok {
			return Ledger{}, fmt.Errorf("migrations: duplicate ledger id %q", entry.ID)
		}
		seenIDs[entry.ID] = struct{}{}
		if entry.Order < 0 || entry.Order <= previousOrder {
			return Ledger{}, errors.New("migrations: ledger order must be non-negative and strictly increasing")
		}
		if _, ok := seenOrders[entry.Order]; ok {
			return Ledger{}, fmt.Errorf("migrations: duplicate ledger order %d", entry.Order)
		}
		seenOrders[entry.Order] = struct{}{}
		previousOrder = entry.Order
		decoded, err := hex.DecodeString(entry.Digest)
		if err != nil || len(decoded) != sha256.Size || entry.Digest != strings.ToLower(entry.Digest) {
			return Ledger{}, fmt.Errorf("migrations: invalid digest for ledger id %q", entry.ID)
		}
	}
	return ledger, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make([]string, 0)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			for _, previous := range seen {
				if strings.EqualFold(previous, key) {
					return fmt.Errorf("duplicate JSON key %q aliases %q", key, previous)
				}
			}
			seen = append(seen, key)
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("invalid object terminator")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return err
}

func migrationDigest(m Migration) (string, error) {
	var settingsContract *MigrationSettings
	if len(m.Settings.Rename) > 0 || len(m.Settings.Delete) > 0 {
		cloned := cloneSettings(m.Settings)
		settingsContract = &cloned
	}
	canonical := struct {
		ID       string             `json:"id"`
		From     string             `json:"from"`
		To       string             `json:"to"`
		Phase    string             `json:"phase"`
		Steps    []MigrationStep    `json:"steps"`
		Settings *MigrationSettings `json:"settings,omitempty"`
	}{m.ID, m.From, m.To, m.Phase, m.Steps, settingsContract}
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("migrations: canonicalize %q: %w", m.ID, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func cloneSettings(in MigrationSettings) MigrationSettings {
	out := MigrationSettings{Delete: append([]string(nil), in.Delete...)}
	if in.Rename != nil {
		out.Rename = make(map[string]string, len(in.Rename))
		for from, to := range in.Rename {
			out.Rename[from] = to
		}
	}
	return out
}

func clone(data []byte) []byte {
	if data == nil {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}
