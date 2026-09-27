package trustverify

// Validate checks the established T3 Tool shape without creating authority,
// receipts, approvals, or performing discovery.
func (t Tool) Validate() error {
	if !tool(t) {
		return &ToolValidationError{}
	}
	return nil
}

type ToolValidationError struct{}

func (*ToolValidationError) Error() string { return "trustverify: invalid tool" }
