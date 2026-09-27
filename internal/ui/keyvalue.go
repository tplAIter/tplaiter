package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// KeyValue — компактный блок "ключ: значение" (шапка `template show`,
// сводки survey/settings) с выравниванием значений по самому длинному ключу
// и единым отступом 2 пробела (см. реализацию реализацию, требование консистентности
// отступов). Порядок пар — порядок вызовов [KeyValue.Add].
type KeyValue struct {
	pairs [][2]string
}

// NewKeyValue создаёт пустой блок.
func NewKeyValue() *KeyValue {
	return &KeyValue{}
}

// Add добавляет пару key/value и возвращает kv для чейнинга. Пустое value
// добавляется как есть — решение пропускать пустые поля остаётся за
// вызывающим кодом.
func (kv *KeyValue) Add(key, value string) *KeyValue {
	kv.pairs = append(kv.pairs, [2]string{key, value})
	return kv
}

// Render пишет блок в w: каждая пара — своя строка "  key: value",
// значения выровнены по самому длинному "key:" среди всех пар.
func (kv *KeyValue) Render(w io.Writer) {
	maxLabel := 0
	for _, p := range kv.pairs {
		if n := lipgloss.Width(p[0]) + 1; n > maxLabel { // +1 за ":"
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

// String возвращает блок как строку без завершающего "\n" сверх последней
// строки — удобно для вставки в более крупный текст (например, в сводку
// survey перед подтверждением, см. internal/survey/flow.go).
func (kv *KeyValue) String() string {
	var b strings.Builder
	kv.Render(&b)
	return strings.TrimSuffix(b.String(), "\n")
}
