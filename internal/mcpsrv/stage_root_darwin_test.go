package mcpsrv

// heldStageRoot exposes the Darwin held-stage directory to transport tests.
func heldStageRoot(s *heldStage) string { return s.root }
