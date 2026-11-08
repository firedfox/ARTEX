package agent

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func executionProbeProvider(name string, input json.RawMessage) captureUsageProvider {
	turn := 0
	return captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
		turn++
		events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "contained"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
		if turn == 1 {
			events = []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "boundary-probe", ToolName: name}, {Type: llm.SEToolInputJSON, Text: string(input)}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
		}
		for _, event := range events {
			if !yield(event, nil) {
				return
			}
		}
	}}
}

func TestExecutionBoundarySDKToolsCannotTouchControlPlane(t *testing.T) {
	for _, name := range []string{"Bash", "Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep", "shell_open", "Monitor", "ExecuteExtraTool", "WebFetch", "web_search", "Skill", "Compress"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "executed")
			secret := filepath.Join(dir, "private-key")
			const value = "synthetic-control-plane-secret"
			if err := os.WriteFile(secret, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(map[string]any{"command": "printf executed > " + marker, "file_path": secret, "path": marker, "content": "executed", "tool_name": "Bash", "input": map[string]any{"command": "printf executed > " + marker}})
			for _, explicit := range []bool{false, true} {
				var tools []actool.CoreTool
				if explicit {
					tools = append(actool.DefaultTools(), actool.ShellSessionTools()...)
				}
				var output strings.Builder
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				_, _, err := captureRun(ctx, agentcore.Options{
					Provider: executionProbeProvider(name, input), Tools: tools, WorkingDir: dir, MaxTurns: 2,
					PermissionMode: permission.ModeBypass, EnableWebFetch: true, EnableWebSearch: true,
					DeferredTools: []string{"Bash"}, UnlockSet: actool.NewUnlockSet("Bash"),
				}, "exercise containment", func(a db.Activity) {
					if a.Kind == "tool_result" {
						output.WriteString(a.Detail)
					}
				})
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("%s created a file (explicit=%v)", name, explicit)
				}
				contents, err := os.ReadFile(secret)
				if err != nil || string(contents) != value {
					t.Fatalf("%s modified the private file", name)
				}
				if strings.Contains(output.String(), value) {
					t.Fatalf("%s exposed a private file", name)
				}
				if output.Len() == 0 {
					t.Fatalf("%s did not exercise the tool dispatch boundary", name)
				}
			}
		})
	}
}

func TestExecutionBoundaryRestoredSessionCannotRestoreShell(t *testing.T) {
	dir := t.TempDir()
	store := transcript.NewStore(filepath.Join(dir, "history"))
	marker := filepath.Join(dir, "executed")
	input, _ := json.Marshal(map[string]any{"command": "printf executed > " + marker})
	opts := agentcore.Options{Provider: executionProbeProvider("Bash", input), Transcript: store, SessionID: "prior-session", Tools: actool.DefaultTools(), WorkingDir: dir, MaxTurns: 2, PermissionMode: permission.ModeBypass}
	prior := newControlPlaneSession(opts)
	if _, _, err := captureRunSession(t.Context(), prior, "attempt old tools", nil); err != nil {
		t.Fatal(err)
	}
	if err := prior.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Provider = executionProbeProvider("Bash", input)
	restored := newControlPlaneSession(opts)
	defer restored.Close()
	if err := restored.Resume("prior-session"); err != nil {
		t.Fatal(err)
	}
	if len(restored.Messages()) == 0 {
		t.Fatal("history was not restored")
	}
	if _, _, err := captureRunSession(t.Context(), restored, "resume the old shell", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("resumed session escaped containment")
	}
}

func TestExecutionBoundaryKeepsExplicitDomainTools(t *testing.T) {
	calls := 0
	probe := actool.Build(actool.Spec{Name: "record_fact", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		calls++
		return actool.Text("recorded"), nil
	}})
	_, _, err := captureRun(t.Context(), agentcore.Options{Provider: executionProbeProvider("record_fact", json.RawMessage(`{}`)), Tools: []actool.CoreTool{probe}, MaxTurns: 2, PermissionMode: permission.ModeBypass}, "organize existing facts", nil)
	if err != nil || calls != 1 {
		t.Fatalf("domain tool calls=%d err=%v", calls, err)
	}
}

func TestExecutionBoundaryNoaDoesNotInitializeFileTools(t *testing.T) {
	dir := t.TempDir()
	opts := agentcore.Options{}
	warned := false
	enableNoa(&opts, func() bool { return true }, dir, "unsafe-context", func(string) { warned = true })
	if !warned || opts.Compactor != nil {
		t.Fatal("Noa was enabled in the control plane")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("Noa created an archive before isolation")
	}
}

// Prevent new/resume/connection-test paths from accidentally constructing an
// unguarded SDK session. Behavioral tests above exercise the actual harness.
func TestExecutionBoundaryAllSessionEntrypointsUsePolicy(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "agentcore" {
				return true
			}
			if selector.Sel.Name == "NewSession" && path != "execution_boundary.go" {
				t.Errorf("unguarded SDK session: %s", path)
			}
			if selector.Sel.Name == "Run" {
				if len(call.Args) < 2 {
					t.Errorf("unexpected SDK call in %s", path)
					return true
				}
				guard, ok := call.Args[1].(*ast.CallExpr)
				if !ok {
					t.Errorf("unguarded SDK run: %s", path)
					return true
				}
				name, ok := guard.Fun.(*ast.Ident)
				if !ok || name.Name != "controlPlaneOptions" {
					t.Errorf("unguarded SDK run: %s", path)
				}
			}
			return true
		})
	}
}
