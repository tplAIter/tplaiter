package resultdto

// ProjectDiffData reports current drift against the authenticated signed baseline.
// It is a read-only observation, never an update plan or execution permission.
type ProjectDiffData struct {
	Offline       bool `json:"offline"`
	FilesChecked  int  `json:"filesChecked"`
	BlocksChecked int  `json:"blocksChecked"`
}
