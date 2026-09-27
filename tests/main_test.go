// Package e2e — чёрный-ящик e2e-харнесс CLI tplater (реализация реализацию).
//
// Все тесты гоняют РЕАЛЬНЫЙ бинарник tplater через os/exec (не вызывают ни
// один internal-пакет напрямую — это отдельный go-модуль, см. go.mod), с
// изолированным TPLAITER_HOME на каждый тест и реальными git file://-репо
// (без сети). Ассерты — по контракту harness_test.go: exit-коды,
// существование файлов/каталогов, валидность JSON, вхождение КЛЮЧЕВЫХ
// подстрок (имена шаблонов/групп, которые контролирует ЭТА реализация через
// testdata/fixtures и inittemplate-скелет), НЕ полные строки вывода —
// оформление вывода (internal/ui, cmd/*) полируется параллельной реализацией
// реализацию и может измениться в любой момент.
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// binPath — путь к собранному бинарнику tplater, готовится один раз в
// TestMain и разделяется всеми тестами пакета (сборка занимает заметное
// время — гонять её на каждый тест было бы расточительно).
var binPath string

// buildVersion — версия, вкомпилированная в тестовый бинарник через
// -ldflags (тот же механизм, что Makefile/CI использует для релиза, см.
// internal/cmd/version.go: resolveVersion). Фиксированная РАЗБИРАЕМАЯ
// semver-версия обязательна для теста версия-гейта (requires.tplaiter,
// internal/newcmd/slug.go: checkTplaterVersion) — сборка БЕЗ ldflags выглядит
// как dev-сборка ("dev"/BuildInfo.Main.Version == "(devel)") и версия-гейт
// для неё эту проверку пропускает ВСЕГДА, что сделало бы весь сценарий 3
// (version-гейт) непроверяемым.
const buildVersion = "v1.0.0"

// TestMain собирает бинарник tplater из корня репозитория (../) во временный
// каталог перед запуском тестов пакета. Код возврата считается отдельной
// функцией [runMain], а не строится из os.Exit внутри самой TestMain — иначе
// `defer os.RemoveAll(tmp)` никогда не выполнился бы (os.Exit не разворачивает
// defer-стек).
func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	tmp, err := os.MkdirTemp("", "tplater-e2e-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: mkdir temp:", err)
		return 1
	}
	defer os.RemoveAll(tmp)

	binPath = filepath.Join(tmp, "tplaiter")
	if err := buildBinary(binPath); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: сборка бинарника tplater:", err)
		return 1
	}

	return m.Run()
}

// buildBinary собирает корневой модуль (../ относительно tests/) в out.
// ldflags проставляет ту же переменную, что и релизный Makefile (LDFLAGS),
// чтобы resolveVersion() вернула buildVersion, а не "dev" (см. её комментарий
// выше). GOWORK=off — сборка идёт как отдельный модуль, воркспейс тут не
// нужен и не должен влиять на список зависимостей.
func buildBinary(out string) error {
	pkg := "github.com/tplAIter/tplaiter/internal/cmd"
	ldflags := fmt.Sprintf("-s -w -X %s.version=%s", pkg, buildVersion)

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", out, ".")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	out2, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build: %w\n%s", err, out2)
	}
	return nil
}
