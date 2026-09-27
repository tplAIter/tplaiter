package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// KeyValue is a compact "key: value" block for `template show` headers and
// survey/settings summaries. It aligns values to the longest key with a uniform
// two-space indent. Pair order is the order of [KeyValue.Add] calls.
type KeyValue struct {
	pairs [][2]string
}

// NewKeyValue creates an empty block.
func NewKeyValue() *KeyValue {
	return &KeyValue{}
}

// Add adds a key/value pair and returns kv for chaining. An empty value is added
// unchanged; the caller decides whether to omit empty fields.
func (kv *KeyValue) Add(key, value string) *KeyValue {
	kv.pairs = append(kv.pairs, [2]string{key, value})
	return kv
}

// Render writes the block to w, one "  key: value" pair per line, aligning values
// to the longest "key:" among all pairs.
func (kv *KeyValue) Render(w io.Writer) {
	maxLabel := 0
	for _, p := range kv.pairs {
		if n := lipgloss.Width(p[0]) + 1; n > maxLabel { // +1 for ":"
			maxLabel = n
		}
	}
	for _, p := range kv.pairs {
		label := p[0] + ":"
		pad := maxLabel - lipgloss.Width(label) + 1
		if pad < 1 {
			pad = 1
		}
		fmt.Fprintf(w, "  %s%s%s\n", label, strings.Repeat(" ", pad), p[1])
	}
}

// String returns the block without an extra trailing "\n", convenient for
// inserting it into larger text such as a survey summary before confirmation.
func (kv *KeyValue) String() string {
	var b strings.Builder
	kv.Render(&b)
	return strings.TrimSuffix(b.String(), "\n")
}
