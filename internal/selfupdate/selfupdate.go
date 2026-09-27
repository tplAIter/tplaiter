// Package selfupdate реализует самообновление CLI tplater:
// определение канала установки, сверку версий с каноническим репозиторием
// через `git ls-remote --tags`, выполнение обновления и ненавязчивую
// фоновую suggest-проверку раз в 24ч.
//
// Весь запуск внешних процессов (git, go install) идёт через
// [github.com/tplAIter/tplaiter/internal/execx.Runner] — пакет не
// трогает os/exec напрямую, чтобы оставаться юнит-тестируемым.
package selfupdate

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// Channel — канал, через который установлен текущий бинарник tplater.
type Channel string

// Поддерживаемые каналы установки (: go install — основной канал,
// brew — дополнительный/будущий, unknown — источник не распознан, например
// бинарник скопирован вручную или собран локально `go build`).
const (
	ChannelGoInstall Channel = "go-install"
	ChannelBrew      Channel = "brew"
	ChannelUnknown   Channel = "unknown"
)

// Label возвращает человекочитаемое имя канала для `tplater version`.
func (c Channel) Label() string {
	switch c {
	case ChannelGoInstall:
		return "go install"
	case ChannelBrew:
		return "brew"
	default:
		return "неизвестен"
	}
}

// RepoEnv — переменная окружения, переопределяющая канонический URL
// репозитория tplater для сверки версий/сборки модуля. Используется тестами,
// чтобы не ходить в реальную сеть, и как временный обходной путь, если
// [DefaultRepoURL] окажется неверным до релиза.
const RepoEnv = "TPLAITER_SELF_REPO"

// DefaultRepoURL — канонический git-репозиторий tplater, используемый для
// `git ls-remote --tags` при сверке версий.
//
// URL подтверждён владельцем (совпадает с module-путём из go.mod, см.
// комментарий там), но заведён отдельной константой, а не выведен из
// BuildInfo.Main.Path: репозиторий шаблонов (upgrade→MR, реализация реализацию) и
// репозиторий CLI могут разойтись в будущем.
const DefaultRepoURL = "https://github.com/tplAIter/tplaiter.git"

// RepoURL возвращает канонический URL репозитория tplater: значение
// [RepoEnv], если оно задано, иначе [DefaultRepoURL].
func RepoURL() string {
	if v := os.Getenv(RepoEnv); v != "" {
		return v
	}
	return DefaultRepoURL
}

// brewPathMarkers — фрагменты пути, характерные для установки бинарника
// Homebrew на macOS (Apple Silicon /opt/homebrew, Intel — /usr/local/Cellar).
// Линуксовый linuxbrew (~/.linuxbrew, /home/linuxbrew) сюда сознательно не
// включён — не входит в целевые платформы
var brewPathMarkers = []string{"/opt/homebrew/", "/usr/local/Cellar/"}

// DetectChannel определяет канал установки текущего исполняемого файла
// tplater: по его пути (go install кладёт бинарники в $GOPATH/bin или
// $HOME/go/bin, brew — в /opt/homebrew или /usr/local/Cellar) и, если путь
// не распознан (например, бинарник скопирован/симлинкнут в произвольный
// каталог PATH), по данным [debug.ReadBuildInfo] — `go install
// module@version` проставляет настоящую версию модуля (не "(devel)").
func DetectChannel() Channel {
	exePath, err := os.Executable()
	if err != nil {
		exePath = ""
	}
	info, _ := debug.ReadBuildInfo()
	return detectChannel(exePath, info, goInstallBinDirs())
}

// goInstallBinDirs возвращает кандидаты каталогов, куда `go install` кладёт
// бинарники: $GOPATH/bin для каждого элемента GOPATH (переменная окружения
// может содержать несколько путей через [filepath.ListSeparator]) и
// $HOME/go/bin — дефолт Go, когда GOPATH не задан явно.
func goInstallBinDirs() []string {
	var dirs []string
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		for _, p := range filepath.SplitList(gopath) {
			if p != "" {
				dirs = append(dirs, filepath.Join(p, "bin"))
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}
	return dirs
}

// detectChannel — чистая функция, вынесенная из [DetectChannel] для
// юнит-тестов: принимает уже вычисленные путь к бинарнику, BuildInfo и
// кандидаты $GOPATH/bin явными аргументами вместо чтения окружения/os.
func detectChannel(exePath string, info *debug.BuildInfo, goBinDirs []string) Channel {
	if exePath != "" {
		for _, marker := range brewPathMarkers {
			if strings.Contains(exePath, marker) {
				return ChannelBrew
			}
		}
		dir := filepath.Dir(exePath)
		for _, d := range goBinDirs {
			if d != "" && dir == d {
				return ChannelGoInstall
			}
		}
	}

	// Фоллбек по BuildInfo: путь не совпал ни с одним известным каталогом
	// (бинарник переставлен/симлинкнут), но версия модуля реальна — это
	// возможно только если бинарник поставлен через `go install
	// module@version` (обычная `go build` оставляет Main.Version == "(devel)").
	if info != nil && info.Main.Path != "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return ChannelGoInstall
	}
	return ChannelUnknown
}
