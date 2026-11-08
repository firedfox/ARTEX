package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
)

func hasSkillTool(tools []actool.CoreTool) bool {
	for _, tool := range tools {
		if tool.Name() == "Skill" {
			return true
		}
	}
	return false
}

func isolateAssemblyHooks(t *testing.T) {
	t.Helper()
	augment, resolve := agent.ToolAugment, agent.ToolResolve
	binding := agent.FindingTrafficBindingEnabled
	t.Cleanup(func() {
		agent.ToolAugment, agent.ToolResolve = augment, resolve
		agent.FindingTrafficBindingEnabled = binding
	})
	// Exercise the augmenter independently of catalog hooks left by another
	// server fixture; domain catalog bindings have their own live-PG tests.
	agent.ToolResolve = nil
	agent.FindingTrafficBindingEnabled = func() bool { return false }
}

func assertAssemblyContained(t *testing.T, tools []actool.CoreTool, def agent.DeferredInfo, expected ...actool.CoreTool) {
	t.Helper()
	if hasSkillTool(tools) {
		t.Fatal("control-plane assembly loaded a filesystem skill")
	}
	if len(def.Deferred) != 0 || len(def.GlobalNames) != 0 || def.Unlock != nil || def.UnlockSkill != nil {
		t.Fatal("control-plane assembly retained deferred execution or a skill unlock callback")
	}
	if len(tools) != len(expected) {
		t.Fatalf("assembled %d tools, want %d allowed domain tools", len(tools), len(expected))
	}
	got := names(tools)
	for _, tool := range expected {
		if got[tool.Name()] == nil {
			t.Fatalf("allowed domain tool %s disappeared", tool.Name())
		}
	}
}

// Visibility remains editable configuration; it must never reactivate local
// skill reads/execution while no isolated runner exists. Both the incoming base
// domain tool and the host-provided domain tool survive the actual wrapper.
func TestExecutionBoundaryVisibleSkillPreservesConfiguration(t *testing.T) {
	s, _ := authSessionFixture(t)
	pg := s.m.pg
	isolateAssemblyHooks(t)
	skillDir := t.TempDir()
	const skillName = "t-assemble"
	if err := os.MkdirAll(filepath.Join(skillDir, skillName), 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: t-assemble\ndescription: do the thing\n---\ndo the thing"
	skillPath := filepath.Join(skillDir, skillName, "SKILL.md")
	if err := os.WriteFile(skillPath, []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	ag, err := pg.GetAgentByKey("planner")
	if err != nil || ag == nil {
		t.Fatalf("planner agent missing: %v", err)
	}
	original, err := pg.AgentSkillNames(ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.SetAgentSkillVisibility(ag.ID, original); err != nil {
			t.Errorf("restore visible skill configuration: %v", err)
		}
	})
	if err := pg.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	ts := agent.NewToolSet(nil, "")
	base, host := ts.GraphOverviewTool(), ts.ListFindingsTool()
	wireAgentAugment(pg, skillDir, func() ([]actool.CoreTool, map[string][]string) {
		return []actool.CoreTool{host}, nil
	})
	assemble := func() {
		// Production callers use AugmentTools, which normalizes an absent
		// resource cleanup to a callable no-op. Do not dereference raw nil cleanup.
		tools, def, cleanup := agent.AugmentTools(t.Context(), "planner", []actool.CoreTool{base})
		defer cleanup()
		assertAssemblyContained(t, tools, def, base, host)
	}
	assemble()
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	assemble()
	visible, err := pg.AgentSkillNames(ag.ID)
	if err != nil || len(visible) != 1 || visible[0] != skillName {
		t.Fatalf("containment changed saved visibility: %v (%v)", visible, err)
	}
	contents, err := os.ReadFile(skillPath)
	if err != nil || string(contents) != md {
		t.Fatal("containment changed the administrator's skill file")
	}
}

// The early refusal also works without a database or a readable skills root.
// This covers the no-resource/nil-cleanup path that the old test called directly.
func TestExecutionBoundaryAssemblyNeedsNoSkillLoader(t *testing.T) {
	isolateAssemblyHooks(t)
	base := agent.NewToolSet(nil, "").GraphOverviewTool()
	wireAgentAugment(nil, filepath.Join(t.TempDir(), "absent-skills"), nil)
	tools, def, cleanup := agent.AugmentTools(t.Context(), "planner", []actool.CoreTool{base})
	defer cleanup()
	assertAssemblyContained(t, tools, def, base)
}
