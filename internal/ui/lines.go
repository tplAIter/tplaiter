package ui

// SuccessLine forms "✓ msg": a success-colored icon and unmodified text. It is
// used for final one-line messages, unlike [Palette.Success], which colors all text.
func SuccessLine(pal Palette, msg string) string { return StatusIcon(pal, StatusOK) + " " + msg }

// WarnLine forms "! msg" with a warning icon.
func WarnLine(pal Palette, msg string) string { return StatusIcon(pal, StatusWarn) + " " + msg }

// ErrorLine forms "✗ msg" with an error icon. It is used, in particular, for
// the "error:" prefix in main.go (see [ErrorPrefix]).
func ErrorLine(pal Palette, msg string) string { return StatusIcon(pal, StatusFail) + " " + msg }

// InfoLine forms a muted informational "ℹ msg" line.
func InfoLine(pal Palette, msg string) string { return pal.Muted("ℹ") + " " + msg }

// ErrorPrefix colors the "error:" prefix with the error palette separately from
// [ErrorLine], because main.go prints the prefix and error text as two Fprintln
// arguments rather than composing one line.
func ErrorPrefix(pal Palette) string { return pal.Error("error:") }
