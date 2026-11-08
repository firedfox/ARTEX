package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/executionpolicy"
	actool "github.com/Autumn-27/norma/tool"
)

func TestExecutionBoundaryDirectCustomCommandsAndSkills(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	s := &Server{skillDir: dir}
	command, _ := json.Marshal(map[string]string{"command": "printf executed > " + marker})
	script, _ := json.Marshal(map[string]string{"code": "open(" + shellQuote(marker) + ", 'w').write('executed')"})
	for name, run := range map[string]func() (actool.Result, error){
		"command": func() (actool.Result, error) { return s.runCommandTool(context.Background(), command, nil, nil) },
		"script":  func() (actool.Result, error) { return s.runScriptTool(context.Background(), "test", script, nil, nil) },
		"create skill": func() (actool.Result, error) {
			return s.toolCreateSkill().Call(context.Background(), json.RawMessage(`{"name":"synthetic","description":"test","instructions":"test"}`), nil)
		},
		"update skill": func() (actool.Result, error) {
			return s.toolUpdateSkillFile().Call(context.Background(), json.RawMessage(`{"name":"synthetic","file":"SKILL.md","content":"test"}`), nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := run()
			if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "isolated task runner") {
				t.Fatalf("executor was not closed: result=%+v err=%v", result, err)
			}
		})
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("a refused tool changed control-plane files")
	}
}

func TestExecutionBoundaryMCPAndScopeSentryDoNotConnect(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	args, _ := json.Marshal([]string{"-c", "printf executed > " + marker})
	for _, transport := range []string{"stdio", "http", "sse"} {
		client, err := connectMCP(t.Context(), &db.MCPServer{Name: "test", Transport: transport, Command: "sh", Args: args, URL: target.URL})
		if client != nil || !errors.Is(err, executionpolicy.ErrIsolatedRunnerRequired) {
			t.Fatalf("%s client escaped containment: %v", transport, err)
		}
	}
	if client, err := (&Server{}).scopeSentryClient(t.Context()); client != nil || !errors.Is(err, executionpolicy.ErrIsolatedRunnerRequired) {
		t.Fatalf("ScopeSentry bypassed the MCP policy: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("MCP reached network before isolation")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("stdio MCP started a process")
	}
}

func TestExecutionBoundaryCustomHTTPAPIRefusesBeforeExecution(t *testing.T) {
	s := &Server{}
	for _, kind := range []string{"command", "script", "http"} {
		body, _ := json.Marshal(map[string]any{"kind": kind, "exec": map[string]any{"command": "exit 0", "code": "print('test')", "url": "http://127.0.0.1:1"}})
		w := httptest.NewRecorder()
		s.pgTestCustomTool(w, httptest.NewRequest("POST", "/api/tools/custom/test", strings.NewReader(string(body))))
		if w.Code != 503 || !strings.Contains(w.Body.String(), "isolated task runner") {
			t.Fatalf("%s HTTP execution status=%d body=%s", kind, w.Code, w.Body.String())
		}
	}
}

func TestExecutionBoundaryStartupDiscoveryDoesNotSpawn(t *testing.T) {
	s, _ := authSessionFixture(t)
	s.ctx = t.Context()
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	args, _ := json.Marshal([]string{"-c", "printf executed > " + marker})
	server := &db.MCPServer{Name: "security-startup-discovery", Transport: "stdio", Command: "sh", Args: args, Enabled: true}
	id, err := s.m.pg.SaveMCP(server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteMCP(id) })
	s.discoverEmptyMCPsOnStartup()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("startup discovery spawned a same-UID process")
	}
}

func TestExecutionBoundarySettingsProbesDoNotConnect(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer target.Close()
	s := &Server{} // Refusal must occur before config/credential lookup as well.
	for _, backend := range []string{"ddgs", "brave", "tavily", "deepseek"} {
		body, err := json.Marshal(map[string]string{"web_search_backend": backend, "web_search_proxy": target.URL})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		s.testWebSearch(w, httptest.NewRequest("POST", "/api/settings/web-search/test", strings.NewReader(string(body))))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s probe status=%d", backend, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.pgDetectPython(w, httptest.NewRequest("POST", "/api/settings/python/detect", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("python probe status=%d", w.Code)
	}
	if requests.Load() != 0 {
		t.Fatal("disabled search probe used the network")
	}
}
