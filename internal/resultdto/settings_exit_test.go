package resultdto

import "testing"

func TestCommittedSettingsConflictExitTwoIsNarrow(t *testing.T) {
	for _, op := range []Operation{OperationSettingsSet, OperationSettingsReanswer, OperationUpdateApply} {
		env := New(op, "test")
		env.Project = &Project{ID: "project", Root: "/work/project"}
		env.Status = StatusConflicted
		env.Summary.Conflicts = 1
		env.Changes = []Change{{Path: "hello.txt", Action: "write"}}
		id := "committed"
		env.TransactionID = &id
		if err := env.ValidateExit(ExitCode(2)); (err == nil) != (op != OperationUpdateApply) {
			t.Fatalf("op=%s: %v", op, err)
		}
		env.TransactionID = nil
		if err := env.ValidateExit(ExitCode(2)); err == nil {
			t.Fatal("uncommitted conflict uses settings committed exit")
		}
	}
	if err := ValidateStatusExit(StatusConflicted, ExitCode(2)); err == nil {
		t.Fatal("generic exit registry changed")
	}
}
