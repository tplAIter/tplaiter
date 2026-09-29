//go:build !darwin && !linux

package mcpsrv

// heldStageRoot has no meaning without a held-stage transport; tests that need
// it skip before calling it on hosts where newHeldStage is unavailable.
func heldStageRoot(*heldStage) string { return "" }
