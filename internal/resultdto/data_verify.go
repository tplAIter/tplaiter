package resultdto

// ProjectVerifyData is the closed read-only verification projection.
type ProjectVerifyData struct {
	Offline         bool   `json:"offline"`
	EntryCount      int    `json:"entryCount"`
	LedgerCount     int    `json:"ledgerCount"`
	DependencyCount int    `json:"dependencyCount"`
	DependencyState string `json:"dependencyState"`
}

type ManagedCheckData struct {
	State    string   `json:"state"`
	Modified []string `json:"modified"`
	Missing  []string `json:"missing"`
	Invalid  []string `json:"invalid"`
}

// ProjectCheckData contains observations, never grants or execution inputs.
type ProjectCheckData struct {
	Offline    bool              `json:"offline"`
	APIVersion string            `json:"apiVersion"`
	Status     string            `json:"status"`
	Managed    ManagedCheckData  `json:"managed"`
	Findings   []string          `json:"findings"`
	Verify     ProjectVerifyData `json:"verify"`
}

// DepsVerifyData attests only to verification of the sealed lock pair.
type DepsVerifyData struct {
	Offline  bool `json:"offline"`
	Verified bool `json:"verified"`
}
