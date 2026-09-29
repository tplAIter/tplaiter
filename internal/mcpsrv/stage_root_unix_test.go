//go:build darwin || linux

package mcpsrv

// heldStageRoot exposes the held-stage directory to transport tests.
func heldStageRoot(s *heldStage) string { return s.root }
