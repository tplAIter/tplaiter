package gen

import (
	"fmt"
	"strings"
)

// insertBeforeAnchor вставляет block перед первой строкой, содержащей
// подстроку anchor (например, "// CODEGEN:WIRING"). Отступы/форматирование
// не нормализуются здесь — автор шаблона вставки отвечает за собственный
// отступ (см. пакетный комментарий gen.go про пост-шаг gofumpt). Ошибка —
// если якорь не найден в content.
func insertBeforeAnchor(content, anchor, block string) (string, error) {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if !strings.Contains(line, anchor) {
			continue
		}
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[:i]...)
		out = append(out, strings.TrimRight(block, "\n"))
		out = append(out, lines[i:]...)
		return strings.Join(out, "\n"), nil
	}
	return "", fmt.Errorf("gen: якорь %q не найден", anchor)
}
