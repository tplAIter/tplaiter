package newcmd

import (
	"io/fs"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/resources"
)

// copyResources copies declared environment, generator, and ai-config
// resources from the template checkout (src) into .tplaiter/ of the created
// project (target). It is a thin wrapper around [resources.Copy]; the logic
// lives in internal/resources so `tplaiter update` can reuse it when copying
// resources from a new template version.
func copyResources(src fs.FS, target string, tpl *manifest.Template) error {
	return resources.Copy(src, target, tpl)
}
