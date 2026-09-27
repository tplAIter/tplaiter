package e2e

import "testing"

// TestMiscCommandsExitZero — таблица команд без побочных эффектов на
// состояние (сценарий 5, требование реализацию): doctor / version / help должны
// завершаться успешно на любой машине с go+git в PATH (doctor.go:
// doctorCriticalTools требует именно go и git — оба обязательны, чтобы
// собрать сам тестовый бинарник, так что критичных провалов здесь быть не
// может).
func TestMiscCommandsExitZero(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{"doctor", []string{"doctor"}},
		{"version", []string{"version"}},
		{"help", []string{"help"}},
		{"root_help_flag", []string{"--help"}},
		{"completion_bash", []string{"completion", "bash"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := newHome(t)
			res := mustRun(t, home, "", tc.args...)
			if res.Stdout == "" && res.Stderr == "" {
				t.Errorf("tplater %v: пустой вывод и на stdout, и на stderr", tc.args)
			}
		})
	}
}

// TestVersionReportsBuildVersion проверяет, что `tplater version` печатает
// РОВНО ту версию, что вкомпилирована ldflags в TestMain (buildVersion) —
// единственная гарантия, что версия-гейт сценария 3 (requires.tplaiter)
// проверяет то, что должен, а не "dev"-заглушку (см. комментарий
// main_test.go:buildVersion).
func TestVersionReportsBuildVersion(t *testing.T) {
	t.Parallel()
	home := newHome(t)
	res := mustRun(t, home, "", "version")
	mustContain(t, res.Stdout, buildVersion, "tplater version")
}
