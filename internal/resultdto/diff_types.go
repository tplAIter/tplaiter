package resultdto

// ProjectDiffData reports current drift against the authenticated signed baseline.
// It is a read-only observation, never an update plan or execution permission.
type ProjectDiffData struct {
	Excluded      []DiffExclusion `json:"excluded,omitempty"`
	Offline       bool            `json:"offline"`
	FilesChecked  int             `json:"filesChecked"`
	BlocksChecked int             `json:"blocksChecked"`
}

// DiffExclusion names the signed reference without conferring writer ownership.
type DiffExclusion struct {
	Path            string `json:"path"`
	Policy          string `json:"policy"`
	Present         bool   `json:"present"`
	CurrentSHA256   string `json:"currentSHA256,omitempty"`
	Mode            uint32 `json:"mode"`
	ExpectedSHA256  string `json:"expectedSHA256"`
	ReferenceCommit string `json:"referenceCommit"`
	ReferenceScope  string `json:"referenceScope"`
	Drift           bool   `json:"drift"`
}
