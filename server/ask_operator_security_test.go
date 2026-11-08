package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/executionpolicy"
)

func TestExecutionBoundaryAskOperatorImageRejectsBeforeTaskLookup(t *testing.T) {
	s := &Server{} // Any attempted task/manager lookup would panic.
	for _, path := range []string{"/proc/self/environ", "/missing/screenshot.png", "relative.png"} {
		input, err := json.Marshal(map[string]string{"question": "read this screenshot", "image_path": path})
		if err != nil {
			t.Fatal(err)
		}
		result, err := s.toolAskOperator().Call(t.Context(), input, nil)
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "isolated task runner") {
			t.Fatalf("image request was not contained before lookup: result=%+v err=%v", result, err)
		}
	}
	result, err := s.toolAskOperator().Call(t.Context(), json.RawMessage(`{"question":"plain question"}`), nil)
	if err != nil || strings.Contains(result.Flatten(), "isolated task runner") || !strings.Contains(result.Flatten(), "worker intent") {
		t.Fatalf("plain question did not reach the existing task-context validation: result=%+v err=%v", result, err)
	}
}

func TestExecutionBoundaryAskOperatorImageCannotCopyHostLinks(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	outside := filepath.Join(base, "private")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("synthetic-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(base, "screenshot.png")
	if err := os.Symlink(outside, image); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{image, "/proc/self/environ", filepath.Join(base, "missing.png")} {
		attachments, err := stageAskOperatorImage(data, "7", path)
		if !errors.Is(err, executionpolicy.ErrIsolatedRunnerRequired) || attachments != nil {
			t.Fatalf("host image was not contained: attachments=%v err=%v", attachments, err)
		}
	}
	if entries, err := os.ReadDir(data); err != nil || len(entries) != 0 {
		t.Fatalf("refused image request changed the workspace: entries=%v err=%v", entries, err)
	}
	if value, err := os.ReadFile(outside); err != nil || string(value) != "synthetic-private-key" {
		t.Fatalf("private source changed: %q %v", value, err)
	}
}
