// Package projectsync приводит запись реестра ~/.tplaiter/projects.yaml,
// отвечающую проекту в текущем рабочем каталоге, в соответствие с фактическим
// состоянием диска (: слежение за путями).
//
// Три сценария, которые обслуживает [SyncCurrent]:
//   - каталог проекта переехал (id тот же, path другой) — path и lastSeenAt
//     обновляются;
//   - проекта нет в реестре (клонирован коллегой, реестр потерян и т.п.) —
//     авто-регистрация: Template/CreatedAt берутся из .tplaiter/project.yaml и
//     текущего момента;
//   - записанный baselineSHA расходится с фактическим содержимым
//     .tplaiter/baseline.json — проект обновляли на другой машине, реестр
//     обновляется по факту.
//
// Все три случая покрываются одним вызовом [state.Projects.Upsert]: его
// контракт (path/lastSeenAt/baselineSHA обновляются всегда, Template/CreatedAt
// фиксируются только при первой вставке) уже реализует ровно это поведение —
// пакету не нужно различать сценарии (а)/(б)/(в) веткой кода.
package projectsync

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/state"
)

// SyncCurrent синхронизирует запись реестра ~/.tplaiter/projects.yaml (домашний
// каталог home) для проекта tplater, обнаруженного от cwd вверх по дереву
// каталогов ([project.FindRoot]). now — временная метка, которая пишется как
// CreatedAt (только при первой вставке) и LastSeenAt.
//
// cwd вне проекта tplater — не ошибка: SyncCurrent возвращает nil, ничего не
// меняя (реестр — удобство навигации, а не источник истины; вне проекта
// синхронизировать нечего). Прочие ошибки (побитый .tplaiter/project.yaml,
// недоступный .tplaiter/baseline.json, лок домашнего каталога) возвращаются
// вызывающему как есть — SyncCurrent сам никогда не паникует и не пишет в
// вывод; решение о том, фатальна ли ошибка для конкретной команды, принимает
// вызывающий (см. cmd.projectSyncPreRun в internal/cmd/projects.go — там она
// не фатальна).
func SyncCurrent(home, cwd string, now time.Time) error {
	root, proj, err := project.FindRoot(cwd)
	if err != nil {
		if errors.Is(err, project.ErrNotInProject) {
			return nil
		}
		return fmt.Errorf("projectsync: поиск корня проекта: %w", err)
	}

	baselineSHA, err := hashFile(filepath.Join(root, engine.BaselineRelPath))
	if err != nil {
		return fmt.Errorf("projectsync: хеш %s: %w", engine.BaselineRelPath, err)
	}

	ref := state.ProjectRef{
		ID:   proj.ID,
		Path: root,
		Template: state.TemplateSelection{
			Repo:    proj.Template.Repo,
			Name:    proj.Template.Name,
			Version: proj.Template.Version,
		},
		CreatedAt:   now,
		LastSeenAt:  now,
		BaselineSHA: baselineSHA,
	}

	return state.WithLock(home, func() error {
		projects, err := state.LoadProjects(home)
		if err != nil {
			return err
		}
		projects.Upsert(ref)
		return state.SaveProjects(home, projects)
	})
}

// hashFile возвращает hex sha256 содержимого файла path (та же формула, что
// [internal/newcmd] использует при первичной регистрации проекта в
// `tplater new`, чтобы значения baselineSHA были сравнимы между собой).
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
