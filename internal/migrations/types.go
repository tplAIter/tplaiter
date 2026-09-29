package migrations

// Migration is an immutable, ordered template-version transition declared by
// a template manifest. Once its ID has been applied to a project, its digest
// is recorded in the migrations ledger and it may never change or move.
//
// The wire tags match the manifest contract byte for byte, so the digest of a
// migration is identical whichever package decoded it.
type Migration struct {
	ID       string            `yaml:"id" json:"id"`
	From     string            `yaml:"from" json:"from"`
	To       string            `yaml:"to" json:"to"`
	Phase    string            `yaml:"phase" json:"phase"`
	Steps    []MigrationStep   `yaml:"steps" json:"steps"`
	Settings MigrationSettings `yaml:"settings" json:"settings,omitempty"`
}

// MigrationStep is executable template input: exactly one of Run or Ansible.
type MigrationStep struct {
	Run      string            `yaml:"run" json:"run,omitempty"`
	Ansible  string            `yaml:"ansible" json:"ansible,omitempty"`
	Optional bool              `yaml:"optional" json:"optional,omitempty"`
	Outputs  []MigrationOutput `yaml:"outputs" json:"outputs,omitempty"`
}

// MigrationOutput binds an executable before-migration to one exact project
// output.
type MigrationOutput struct {
	Path   string `yaml:"path" json:"path"`
	SHA256 string `yaml:"sha256" json:"sha256"`
}

// MigrationSettings applies deterministic key-only transformations to the
// recorded settings answers.
type MigrationSettings struct {
	Rename map[string]string `yaml:"rename" json:"rename,omitempty"`
	Delete []string          `yaml:"delete" json:"delete,omitempty"`
}

// Executable reports whether the migration runs template-provided code.
func (m Migration) Executable() bool { return len(m.Steps) > 0 }
