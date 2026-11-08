package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Model skill writers may not mutate the control plane, even with valid paths.
// Manual skills HTTP operations are independently exercised by rooted-fs tests.
func TestExecutionBoundarySkillToolsDoNotWrite(t *testing.T) {
	dir := t.TempDir()
	s := &Server{skillDir: dir}
	for _, name := range []string{"my-skill", "Bad Name"} {
		in, _ := json.Marshal(map[string]any{"name": name, "description": "does X", "instructions": "## do\n1. a"})
		result, err := s.toolCreateSkill().Call(context.Background(), in, nil)
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "isolated task runner") {
			t.Fatalf("create_skill was not refused: err=%v result=%+v", err, result)
		}
	}
	for _, path := range []string{"SKILL.md", "scripts/run.py", "../escape.txt"} {
		in, _ := json.Marshal(map[string]any{"name": "my-skill", "file": path, "content": "test"})
		result, err := s.toolUpdateSkillFile().Call(context.Background(), in, nil)
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "isolated task runner") {
			t.Fatalf("update_skill_file was not refused: err=%v result=%+v", err, result)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("model skill tools changed the filesystem")
	}
}
