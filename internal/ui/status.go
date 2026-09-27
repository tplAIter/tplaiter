package ui

// StatusKind is the semantic state of a report item or table row: environment
// check (doctor), registry-record availability (projects list), when-condition
// satisfiability (run/env/gen/ai list), or a declared but unimplemented manifest
// option (template show, planned).
type StatusKind int

const (
	// StatusOK means the check/item is in order.
	StatusOK StatusKind = iota
	// StatusWarn is noncritical but needs attention (an optional tool is absent
	// or a registry record is questionable).
	StatusWarn
	// StatusFail is critical (a required tool is absent or an error occurred).
	StatusFail
	// StatusPlanned is declared by the manifest but not yet implemented; planned
	// options remain visible but muted.
	StatusPlanned
)

// StatusIcon returns a pal-colored state symbol: ✓ (OK), ! (Warn), ✗ (Fail),
// or ○ (muted Planned). When pal.Enabled() is false it returns the symbol
// without ANSI color; unlike color, the icon carries meaning by itself.
func StatusIcon(pal Palette, kind StatusKind) string {
	switch kind {
	case StatusOK:
		return pal.Success("✓")
	case StatusWarn:
		return pal.Warn("!")
	case StatusFail:
		return pal.Error("✗")
	case StatusPlanned:
		return pal.Muted("○")
	default:
		return ""
	}
}
