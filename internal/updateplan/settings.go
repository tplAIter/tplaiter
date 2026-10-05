package updateplan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

// ErrSettingsInput identifies invalid operator settings, never writer authority.
var ErrSettingsInput = errors.New("native settings: invalid overrides")

func cloneSettingsInput(in Input) (Input, error) {
	if len(in.SettingsPairs) > 128 {
		return Input{}, ErrSettingsInput
	}
	size := 0
	for _, pair := range in.SettingsPairs {
		size += len(pair)
		if len(pair) == 0 || len(pair) > 4096 || size > 65536 {
			return Input{}, ErrSettingsInput
		}
	}
	if len(in.SettingsPairs) > 0 && !bytes.Equal(in.SourceInput, in.TargetInput) {
		return Input{}, ErrSettingsInput
	}
	return Input{SourceInput: bytes.Clone(in.SourceInput), TargetInput: bytes.Clone(in.TargetInput), SettingsPairs: append([]string(nil), in.SettingsPairs...)}, nil
}

func settingsValuesEqual(a, b settings.Values) bool { return reflect.DeepEqual(a, b) }

// ResolveSettingsPairs retains non-default current answers and lets requires
// imply default-equal groups, exactly as the settings resolver contract intends.
func ResolveSettingsPairs(tpl *manifest.Template, old settings.Values, pairs []string) (settings.Resolved, error) {
	defaults := settings.DefaultValues(tpl)
	explicit := settings.Values{}
	for k, v := range old {
		if !reflect.DeepEqual(v, defaults[k]) {
			explicit[k] = v
		}
	}
	return resolveSettingsExplicit(tpl, explicit, pairs, renderref.Values(old))
}

func resolveSettingsExplicit(tpl *manifest.Template, explicit settings.Values, pairs []string, prior settings.Values) (settings.Resolved, error) {
	if _, err := cloneSettingsInput(Input{SettingsPairs: pairs}); err != nil {
		return settings.Resolved{}, err
	}
	intent := settings.DefaultValues(tpl)
	for key, value := range prior {
		intent[key] = value
	}
	seen := map[string]bool{}
	var submitted []string
	for _, pair := range pairs {
		key, value, err := settings.ParseRecordedSet(tpl, pair, prior)
		if err != nil {
			return settings.Resolved{}, fmt.Errorf("%w: %w", ErrSettingsInput, err)
		}
		if seen[key] {
			return settings.Resolved{}, fmt.Errorf("%w: duplicate group %q", ErrSettingsInput, key)
		}
		seen[key] = true
		submitted = append(submitted, key)
		explicit[key] = value
		intent[key] = value
	}
	// Only recorded ancestry plus explicit parent choices may expose a group.
	// Default recomputation or requires implication alone cannot authorize an
	// originally hidden descendant override.
	for _, key := range submitted {
		if !SettingsGroupActive(tpl, intent, key) {
			return settings.Resolved{}, fmt.Errorf("%w: inactive group %q", ErrSettingsInput, key)
		}
	}
	resolved, err := settings.ResolveRecorded(tpl, prior, explicit)
	if err != nil {
		return settings.Resolved{}, fmt.Errorf("%w: %w", ErrSettingsInput, err)
	}
	for _, key := range submitted {
		if !SettingsGroupActive(tpl, resolved.Values, key) {
			return settings.Resolved{}, fmt.Errorf("%w: inactive group %q", ErrSettingsInput, key)
		}
	}
	return resolved, nil
}

func (b *Backend) settingsRender(ctx context.Context, in Input, old renderref.Input, answers map[string]stateledger.Answer) (renderref.Input, error) {
	if len(in.SettingsPairs) == 0 {
		return old, nil
	}
	if _, err := cloneSettingsInput(in); err != nil {
		return renderref.Input{}, err
	}
	raw, err := b.verifiedManifest(ctx, in.SourceInput)
	if err != nil {
		return renderref.Input{}, err
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		return renderref.Input{}, err
	}
	if err := tpl.Validate(); err != nil {
		return renderref.Input{}, err
	}
	resolved, err := ResolveSettingsAnswers(tpl, answers, in.SettingsPairs)
	if err != nil {
		return renderref.Input{}, err
	}
	old.Values = renderref.Values(resolved.Values)
	return old, nil
}
