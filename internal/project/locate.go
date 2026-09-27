// Package project реализует обнаружение проекта tplater из произвольного
// рабочего каталога и разрешение манифеста шаблона, к которому этот проект
// привязан (: базовая инфраструктура для `tplater run`).
//
// Пакет НЕ читает и не пишет реестр ~/.tplaiter/projects.yaml —
// это ответственность отдельной реализации; здесь только поиск локального
// маркера .tplaiter/project.yaml вверх по дереву каталогов и разрешение
// манифеста шаблона по зафиксированной в этом маркере версии.
package project

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/naming"
)

// MarkerRelPath — путь проектного маркера относительно корня проекта
//.
const MarkerRelPath = ".tplaiter/project.yaml"

// LegacyMarkerRelPath remains read-only compatibility. Writers always use
// MarkerRelPath, and two markers at one root are ambiguous rather than merged.
const LegacyMarkerRelPath = ".tplater/project.yaml"

// ErrNotInProject возвращается [FindRoot], когда ни в стартовом каталоге, ни
// в одном из родительских (до $HOME или корня файловой системы) не нашлось
// .tplaiter/project.yaml. errors.Is различает эту ситуацию от прочих ошибок
// файловой системы/разбора, которые FindRoot возвращает как есть.
var ErrNotInProject = errors.New("каталог не является проектом tplater")

// FindRoot ищет корень проекта tplater, поднимаясь от startDir вверх по
// дереву каталогов до первого найденного .tplaiter/project.yaml. Поиск
// останавливается (не поднимаясь выше) на домашнем каталоге пользователя
// ($HOME, если он определён) или на корне файловой системы — оба
// проверяются последними перед остановкой, так что маркер прямо в $HOME или
// в "/" тоже был бы найден.
//
// root — абсолютный путь каталога, содержащего .tplaiter/project.yaml (не
// сам файл и не .tplaiter). proj — разобранный маркер этого каталога.
//
// Ошибки: [ErrNotInProject] (обёрнутая, с человекочитаемым сообщением), если
// поиск дошёл до границы и ничего не нашёл; ошибка разбора startDir/маркера
// — если маркер найден, но не читается или невалиден (это не "нет проекта",
// а "проект сломан" — вызывающий должен различать их через errors.Is).
func FindRoot(startDir string) (root string, proj *manifest.Project, err error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", nil, fmt.Errorf("project: определение абсолютного пути для %s: %w", startDir, err)
	}
	dir = filepath.Clean(dir)

	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		home = filepath.Clean(home)
	}

	for {
		markerPath := filepath.Join(dir, MarkerRelPath)
		legacyPath := filepath.Join(dir, LegacyMarkerRelPath)
		_, modernErr := os.Stat(markerPath)
		_, legacyErr := os.Stat(legacyPath)
		// os.Stat of a child below a regular tombstone reports ENOTDIR, which
		// is neither a modern/legacy marker pair nor an absence. Do not let it
		// bypass receipt verification merely because the modern marker exists.
		if legacyInfo, err := os.Lstat(filepath.Join(dir, naming.LegacyProjectDir)); err == nil && legacyInfo.Mode().IsRegular() {
			migrated, migrationErr := naming.MigratedProjectRoot(dir)
			if migrationErr != nil {
				return "", nil, fmt.Errorf("project: verify migration in %s: %w", dir, migrationErr)
			}
			if !migrated {
				return "", nil, fmt.Errorf("project: unverified legacy tombstone in %s", dir)
			}
			legacyErr = os.ErrNotExist
		}
		if modernErr == nil && legacyErr == nil {
			migrated, migrationErr := naming.MigratedProjectRoot(dir)
			if migrationErr != nil {
				return "", nil, fmt.Errorf("project: verify migration in %s: %w", dir, migrationErr)
			}
			if !migrated {
				return "", nil, fmt.Errorf("project: both modern and legacy markers exist in %s", dir)
			}
			legacyErr = os.ErrNotExist
		}
		if os.IsNotExist(modernErr) && legacyErr == nil {
			markerPath, modernErr = legacyPath, nil
		}
		switch {
		case modernErr == nil:
			p, loadErr := manifest.LoadProject(markerPath)
			if loadErr != nil {
				return "", nil, fmt.Errorf("project: загрузка маркера проекта %s: %w", markerPath, loadErr)
			}
			return dir, p, nil
		case !os.IsNotExist(modernErr):
			return "", nil, fmt.Errorf("project: проверка маркера проекта %s: %w", markerPath, modernErr)
		case !os.IsNotExist(legacyErr):
			return "", nil, fmt.Errorf("project: проверка legacy-маркера проекта %s: %w", legacyPath, legacyErr)
		}

		if homeErr == nil && dir == home {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // корень файловой системы — выше не поднимаемся.
		}
		dir = parent
	}

	return "", nil, fmt.Errorf(
		"%w: не найден %s ни в %s, ни в одном из родительских каталогов — "+
			"команда должна выполняться внутри проекта, созданного `tplater new`",
		ErrNotInProject, MarkerRelPath, startDir,
	)
}
