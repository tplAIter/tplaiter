package resultdto

// ProjectLinkData describes state-only signed link/adopt or its authenticated recovery.
type ProjectLinkData struct {
	Action           string                `json:"action"`
	DryRun           bool                  `json:"dryRun"`
	Ref              string                `json:"ref"`
	TrackedConflicts []LinkOwnershipChoice `json:"trackedConflicts"`
}
type LinkOwnershipChoice struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	Choice string `json:"choice"`
}
