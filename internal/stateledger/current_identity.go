package stateledger

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
)

// CheckCurrentProjectIdentity preserves the canonical current-marker diagnostic
// before native inventory projects a journal status. It checks actual confined
// marker bytes twice, never a caller-supplied expected ID or historical image.
func CheckCurrentProjectIdentity(ctx context.Context, root string, authority BindingAuthority) error {
	if ctx == nil {
		return ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, _, err := validateRoots(root, "")
	if err != nil {
		return err
	}
	path := filepath.Join(root, StateDir, "project.yaml")
	before, mode, err := stableReadWithMode(path)
	if err != nil {
		return err
	}
	var marker ProjectV2
	if err := decodeYAMLStrict(before, &marker); err != nil {
		return fmt.Errorf("%w: marker: %w", ErrUnsafe, err)
	}
	if err := validateV2(marker); err != nil {
		return err
	}
	if err := checkProjectIdentity(ctx, authority, root, marker.ID); err != nil {
		return err
	}
	after, currentMode, err := stableReadWithMode(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) || mode != currentMode {
		return ErrUnsafe
	}
	return ctx.Err()
}
