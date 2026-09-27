package newcmd

import (
	"io/fs"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/resources"
)

// copyResources переносит из checkout шаблона (src) в .tplaiter/ созданного
// проекта (target) декларированные ресурсы окружения/генераторов/ai-config.
// Тонкая обёртка над [resources.Copy]: та же логика вынесена в общий пакет
// internal/resources (реализация ), чтобы её без дублирования переиспользовал
// `tplater update` при перекопировании ресурсов новой версии шаблона.
func copyResources(src fs.FS, target string, tpl *manifest.Template) error {
	return resources.Copy(src, target, tpl)
}
