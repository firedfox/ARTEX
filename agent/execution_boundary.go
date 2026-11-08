package agent

import (
	"context"
	"strings"

	"github.com/Autumn-27/artex/internal/executionpolicy"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// Do not use DefaultTools in the control plane: Read/Write are as capable of
// exposing signing keys or /proc as Bash, even when no subprocess is launched.
func controlPlaneTools() []actool.CoreTool { return []actool.CoreTool{actool.NewSleep()} }

func controlPlaneToolAllowed(name string) bool {
	switch name {
	case "Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep", "Bash",
		"WebFetch", "web_search", "Skill", "Compress", "SearchExtraTools", "ExecuteExtraTool",
		"TaskOutput", "TaskStop", "TaskList", "Monitor", "create_skill", "update_skill_file":
		return false
	}
	return !strings.HasPrefix(name, "shell_") && !strings.HasPrefix(name, "mcp__")
}

// Applied to EVERY SDK session, including connection tests and goal extraction.
// A non-nil empty Tools slice is required: nil enables the SDK's default shell
// and unrestricted filesystem tools. Disable SDK auto-injection as well as the
// explicit list; clearing only Options.Tools leaves background/deferred tools.
func controlPlaneOptions(opts agentcore.Options) agentcore.Options {
	permitted := make([]actool.CoreTool, 0, len(opts.Tools))
	allowed := map[string]bool{}
	for _, t := range opts.Tools {
		if controlPlaneToolAllowed(t.Name()) {
			permitted = append(permitted, t)
			allowed[t.Name()] = true
		}
	}
	opts.Tools = permitted
	opts.EnableWebFetch = false
	opts.EnableWebSearch = false
	opts.DisableBackgroundTasks = true
	opts.Memory = nil
	opts.Plan = nil
	opts.Skills = nil
	opts.DeferredTools = nil
	opts.UnlockSet = nil
	opts.Compactor = nil // no model-driven Noa file tools in this process
	if opts.Todos != nil {
		allowed[opts.Todos.Tool().Name()] = true
	}
	if opts.AskUser != nil {
		allowed[actool.NewAskUserQuestion(opts.AskUser).Name()] = true
	}
	opts.Hooks = &controlPlaneHooks{next: opts.Hooks, allowed: allowed}
	opts.SystemPrompt = append(append([]string{}, opts.SystemPrompt...), "This instance is in control-plane-only containment. You may discuss and organize stored task data using available domain tools. Active probes, local files, shell/Python, browser/MCP and custom executors are unavailable until an isolated runner is installed and verified. State this limitation when relevant; never claim those actions were performed.")
	return opts
}

func newControlPlaneSession(opts agentcore.Options) *agentcore.Session {
	return agentcore.NewSession(controlPlaneOptions(opts))
}

type controlPlaneHooks struct {
	next    harness.HookRunner
	allowed map[string]bool
}

func (h *controlPlaneHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if !h.allowed[name] || !controlPlaneToolAllowed(name) {
		return true, executionpolicy.ErrIsolatedRunnerRequired.Error(), nil
	}
	if h.next != nil {
		return h.next.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}
func (h *controlPlaneHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.next != nil {
		h.next.PostToolUse(ctx, name, input, result, isErr)
	}
}
func (h *controlPlaneHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.next != nil {
		return h.next.Stop(ctx, messages)
	}
	return false, nil, ""
}
