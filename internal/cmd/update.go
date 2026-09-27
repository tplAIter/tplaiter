package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"github.com/tplAIter/tplaiter/internal/update"
)

// updateRunner — Runner для postUpdate-хуков команды `tplater update`. Пакетная
// переменная по образцу newRunner/runRunner для подмены в тестах.
var updateRunner execx.Runner = execx.Exec{}

func init() {
	rootCmd.AddCommand(newUpdateCmd())
}

// newUpdateCmd создаёт команду `tplater update`: 3-way обновление
// проекта на новую версию шаблона с отчётом по 5 категориям и конфликт-маркерами.
func newUpdateCmd() *cobra.Command {
	var (
		to          string
		all         bool
		dryRun      bool
		check       bool
		sourceInput string
	)

	c := &cobra.Command{
		Use:   "update",
		Short: "Обновить проект на новую версию шаблона (3-way merge)",
		Long: "Обновляет сгенерированный проект на целевую версию шаблона по модели 3-way merge " +
			"(): base — чистый рендер зафиксированной версии, target — рендер новой, " +
			"пользовательские правила определяются по .tplaiter/baseline.json. Непересекающиеся " +
			"правки сливаются автоматически, пересекающиеся дают конфликт-маркеры " +
			"(<<<<<<< / ======= / >>>>>>>) и код выхода 2.\n\n" +
			"Без --to берётся старший стабильный тег из кеша репозитория (`tplater repo update` " +
			"подтягивает новые теги). --dry-run считает план без записи; --check сканирует дерево " +
			"на оставшиеся маркеры конфликта (код выхода 1); --all обходит все проекты реестра.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				return update.ErrLifecycleUnavailable
			}
			if check {
				return checkLocalConflicts(cmd)
			}
			runtime, err := composeRuntime(cmd.Context())
			if err != nil {
				return err
			}
			defer runtime.Close()
			if !dryRun {
				return update.ErrLifecycleUnavailable
			}
			if sourceInput == "" {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			target, err := readUntrustedDocument(cmd.Context(), sourceInput)
			if err != nil {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			targetSelection, err := operationtrust.DecodeSourceSelection(target)
			if err != nil || (to != "" && targetSelection.Subject.Commit != to) {
				return errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
			}
			source, err := registeredSourceInput(cmd.Context(), runtime)
			if err != nil {
				return err
			}
			preimage, err := registeredProjectPreimage(cmd.Context(), runtime.ProjectContext().RootPath)
			if err != nil {
				return err
			}
			prepared, err := update.Prepare(cmd.Context(), runtime, operationtrust.PrepareUpdateInput{SourceInput: source, TargetInput: target, Render: renderref.Input{}, RendererVersion: resolveVersion(), PreimageSHA256: preimage})
			if err != nil {
				return err
			}
			if !prepared.ValidFor(runtime.TrustRuntime()) {
				return errors.New("TRUST_RUNTIME_INVALID")
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "dry-run prepared")
			return nil
		},
	}

	f := c.Flags()
	f.StringVar(&to, "to", "", "целевая версия шаблона (по умолчанию — старший стабильный тег)")
	f.BoolVar(&all, "all", false, "обновить все проекты реестра со статусом ok")
	f.BoolVar(&dryRun, "dry-run", false, "показать план без изменения файлов")
	f.BoolVar(&check, "check", false, "проверить дерево на маркеры конфликта (код выхода 1 при находке)")
	f.StringVar(&sourceInput, "source-input", "", "закрытый JSON выбора целевого источника")
	return c
}

// registeredSourceInput reads the existing project pair at its fixed metadata
// paths. The pair is only an assertion until it passes its strict decoders,
// pair validation, exact active profile comparison, and the fresh verification
// performed by operationtrust.PrepareUpdate.
func registeredSourceInput(ctx context.Context, runtime interface {
	ProjectContext() trustload.ProjectContext
	TrustRuntime() *trustverify.Runtime
}) ([]byte, error) {
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	project := runtime.ProjectContext()
	rootRaw, err := readRegisteredLock(ctx, project.RootPath, "root-template.lock.json")
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	depsRaw, err := readRegisteredLock(ctx, project.RootPath, "template.lock.json")
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	root, err := provenance.DecodeRootTemplateLock(rootRaw)
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	deps, err := provenance.DecodeTemplateLock(depsRaw)
	if err != nil || provenance.ValidateLockPair(*root, *deps) != nil || !root.TrustProfile.Equal(runtime.TrustRuntime().Binding()) || !deps.TrustProfile.Equal(runtime.TrustRuntime().Binding()) {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	s := root.Root
	selection := operationtrust.SourceSelection{APIVersion: operationtrust.SourceSelectionAPIVersion, Subject: operationtrust.SelectionSubject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}, Evidence: operationtrust.SelectionEvidence{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS}, Dependencies: []string{}}
	raw, err := json.Marshal(selection)
	if err != nil {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	return raw, nil
}

// registeredProjectPreimage is a bounded, local-only snapshot digest used by
// preparation. It never follows symlinks or leaves the registered root.
func registeredProjectPreimage(ctx context.Context, root string) (string, error) {
	if ctx == nil || root == "" || !filepath.IsAbs(root) {
		return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	var paths []string
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return errors.New("scan")
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || !fs.ValidPath(filepath.ToSlash(rel)) || entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("scan")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || len(paths) >= 4096 {
			return errors.New("scan")
		}
		info, err := entry.Info()
		if err != nil || info.Size() < 0 || total+info.Size() > 64<<20 {
			return errors.New("scan")
		}
		total += info.Size()
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	sort.Strings(paths)
	h := sha256.New()
	remaining := int64(64 << 20)
	for _, rel := range paths {
		if _, err := h.Write([]byte(rel)); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		if _, err := h.Write([]byte{0}); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		data, err := readRegisteredPreimageFile(ctx, root, rel, remaining)
		if err != nil || int64(len(data)) > remaining || ctx.Err() != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		remaining -= int64(len(data))
		if _, err := h.Write(data); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		if _, err := h.Write([]byte{0}); err != nil {
			return "", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func checkLocalConflicts(cmd *cobra.Command) error {
	// --check is intentionally local and bounded; it does not load a manager,
	// source ref, registry, or publisher. The project root is the current dir.
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	found, err := update.ScanConflicts(root, nil)
	if err != nil {
		return err
	}
	for _, path := range found {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), path)
	}
	if len(found) != 0 {
		return &ExitError{Code: 1, Err: errors.New("conflict markers found")}
	}
	return nil
}
