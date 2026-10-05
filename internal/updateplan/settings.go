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
	seen := map[string]bool{}
	for _, pair := range pairs {
		key, value, err := settings.ParseSet(tpl, pair)
		if err != nil {
			return settings.Resolved{}, fmt.Errorf("%w: %w", ErrSettingsInput, err)
		}
		if seen[key] {
			return settings.Resolved{}, fmt.Errorf("%w: duplicate group %q", ErrSettingsInput, key)
		}
		seen[key] = true
		explicit[key] = value
	}
	resolved, err := settings.Resolve(tpl, explicit)
	if err != nil {
		return settings.Resolved{}, fmt.Errorf("%w: %w", ErrSettingsInput, err)
	}
	return resolved, nil
}

func (b *Backend) settingsRender(ctx context.Context, in Input, old renderref.Input) (renderref.Input, error) {
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
	resolved, err := ResolveSettingsPairs(tpl, old.Values, in.SettingsPairs)
	if err != nil {
		return renderref.Input{}, err
	}
	old.Values = renderref.Values(resolved.Values)
	return old, nil
}
