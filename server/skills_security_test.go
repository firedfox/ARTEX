package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

func skillsSecurityFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, root, outside := workspaceSecurityFixture(t)
	s.skillDir = root
	return s, root, outside
}

func skillsSecurityRequest(t *testing.T, method, name, file string, body any) *http.Request {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, "/api/skills", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("name", name)
	req.SetPathValue("file", file)
	return req
}

func skillsSecurityCall(t *testing.T, handler http.HandlerFunc, method, name, file string, body any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(rec, skillsSecurityRequest(t, method, name, file, body))
	return rec
}

func skillsSecurityZipRequest(t *testing.T, name string, overwrite bool) *http.Request {
	t.Helper()
	data := buildZip(t,
		zipFile{name: name + "/SKILL.md", body: "---\nname: " + name + "\ndescription: inside description\n---\ninside body\n", method: zip.Deflate},
		zipFile{name: name + "/references/notes.md", body: "inside notes", method: zip.Deflate},
	)
	target := "/api/skills/upload"
	if overwrite {
		target += "?overwrite=true"
	}
	req, err := workspaceSecurityUpload(target, name+".zip", string(data))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestWorkspaceSecuritySkillsNormalLifecycle(t *testing.T) {
	s, root, _ := skillsSecurityFixture(t)
	rec := skillsSecurityCall(t, s.fsCreateSkill, "POST", "", "", map[string]any{
		"name": "demo", "description": "inside: description", "mcps": []string{"one", "two"}, "instructions": "inside body",
	})
	if rec.Code != 201 {
		t.Fatalf("create=%d %s", rec.Code, rec.Body)
	}
	rec = skillsSecurityCall(t, s.fsListSkills, "GET", "", "", nil)
	var listing struct{ Skills []skillFileNode }
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &listing) != nil || len(listing.Skills) != 1 ||
		listing.Skills[0].Description != "inside: description" || len(listing.Skills[0].MCPs) != 2 {
		t.Fatalf("list=%d %s", rec.Code, rec.Body)
	}
	rec = skillsSecurityCall(t, s.fsUpdateSkillMeta, "PUT", "demo", "", map[string]any{"description": "updated: description", "mcps": []string{"three"}})
	if rec.Code != 200 {
		t.Fatalf("metadata=%d %s", rec.Code, rec.Body)
	}
	rec = skillsSecurityCall(t, s.fsReadFile, "GET", "demo", "SKILL.md", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "updated: description") || !strings.Contains(rec.Body.String(), "inside body") {
		t.Fatalf("read=%d %s", rec.Code, rec.Body)
	}
	rec = skillsSecurityCall(t, s.fsWriteFile, "PUT", "demo", "references/中文 notes.md", map[string]string{"content": "inside reference"})
	if rec.Code != 200 {
		t.Fatalf("write=%d %s", rec.Code, rec.Body)
	}
	rec = skillsSecurityCall(t, s.fsCreateDir, "POST", "demo", "", map[string]string{"path": "assets/empty"})
	if rec.Code != 201 {
		t.Fatalf("mkdir=%d %s", rec.Code, rec.Body)
	}
	rec = skillsSecurityCall(t, s.fsListFiles, "GET", "demo", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "references/中文 notes.md") || !strings.Contains(rec.Body.String(), "assets/empty/") {
		t.Fatalf("files=%d %s", rec.Code, rec.Body)
	}
	if err := os.Symlink("references/中文 notes.md", filepath.Join(root, "demo", "inside-link")); err != nil {
		t.Fatal(err)
	}
	rec = skillsSecurityCall(t, s.fsReadFile, "GET", "demo", "inside-link", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "inside reference") {
		t.Fatalf("inside link=%d %s", rec.Code, rec.Body)
	}
	rec = skillsSecurityCall(t, s.fsDeletePath, "DELETE", "demo", "assets", nil)
	if rec.Code != 200 {
		t.Fatalf("delete=%d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	s.fsUploadSkill(rec, skillsSecurityZipRequest(t, "demo", true))
	if rec.Code != 201 {
		t.Fatalf("overwrite=%d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(root, "demo", "references/notes.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "demo", "inside-link")); !os.IsNotExist(err) {
		t.Fatalf("overwrite retained an old file: %v", err)
	}
}

func TestWorkspaceSecuritySkillsRejectExistingLinks(t *testing.T) {
	s, root, outside := skillsSecurityFixture(t)
	secret := filepath.Join(outside, "SKILL.md")
	const secretBody = "---\nname: outside\ndescription: outside-private-content\n---\noutside-private-content\n"
	workspaceSecurityFile(t, secret, secretBody)
	workspaceSecurityFile(t, filepath.Join(root, "demo", "inside.txt"), "inside")
	for path, target := range map[string]string{
		"alias":         outside,
		"demo/escape":   outside,
		"demo/SKILL.md": secret,
	} {
		if err := os.Symlink(target, filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"demo", "alias"} {
		workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsReadFile, "GET", name, "SKILL.md", nil), outside)
		workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsWriteFile, "PUT", name, "SKILL.md", map[string]string{"content": "must stay inside"}), outside)
		workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsUpdateSkillMeta, "PUT", name, "", map[string]string{"description": "must stay inside"}), outside)
	}
	workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsListFiles, "GET", "alias", "", nil), outside)
	workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsCreateSkill, "POST", "", "", map[string]string{"name": "alias", "description": "must stay inside"}), outside)
	workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsCreateDir, "POST", "demo", "", map[string]string{"path": "escape/new-dir"}), outside)
	workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsDeletePath, "DELETE", "demo", "escape/SKILL.md", nil), outside)
	list := skillsSecurityCall(t, s.fsListSkills, "GET", "", "", nil)
	if list.Code != 200 || strings.Contains(list.Body.String(), "outside-private-content") {
		t.Fatalf("metadata listing escaped=%d %s", list.Code, list.Body)
	}
	// An escaping link can be removed without touching the target.
	removed := skillsSecurityCall(t, s.fsDeletePath, "DELETE", "demo", "escape", nil)
	if removed.Code != 200 {
		t.Fatalf("remove link=%d %s", removed.Code, removed.Body)
	}
	conflict := httptest.NewRecorder()
	s.fsUploadSkill(conflict, skillsSecurityZipRequest(t, "alias", false))
	if conflict.Code != 409 {
		t.Fatalf("upload alias conflict=%d %s", conflict.Code, conflict.Body)
	}
	// Overwrite removes the alias itself, then renames an in-root stage into place.
	installed := httptest.NewRecorder()
	s.fsUploadSkill(installed, skillsSecurityZipRequest(t, "alias", true))
	if installed.Code != 201 {
		t.Fatalf("replace alias=%d %s", installed.Code, installed.Body)
	}
	if info, err := os.Lstat(filepath.Join(root, "alias")); err != nil || !info.IsDir() {
		t.Fatalf("upload did not replace the link with a directory: %v", err)
	}
	if got, err := os.ReadFile(secret); err != nil || string(got) != secretBody {
		t.Fatalf("outside skill changed: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "new-dir")); !os.IsNotExist(err) {
		t.Fatalf("created a directory outside skills: %v", err)
	}
}

func TestWorkspaceSecuritySkillsRejectConfiguredRootLinks(t *testing.T) {
	s, root, outside := skillsSecurityFixture(t)
	workspaceSecurityFile(t, filepath.Join(outside, "demo/SKILL.md"), "---\nname: demo\ndescription: outside-private-content\n---\nbody\n")
	alias := filepath.Join(root, "root-alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatal(err)
	}
	// Cover a link at the configured root and in one of its ancestors.
	for _, dir := range []string{alias, filepath.Join(alias, "demo")} {
		s.skillDir = dir
		workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsListSkills, "GET", "", "", nil), outside)
		workspaceSecurityDenied(t, skillsSecurityCall(t, s.fsCreateSkill, "POST", "", "", map[string]string{"name": "new-skill", "description": "must stay inside"}), outside)
		rec := httptest.NewRecorder()
		s.fsUploadSkill(rec, skillsSecurityZipRequest(t, "new-skill", false))
		workspaceSecurityDenied(t, rec, outside)
	}
	for _, path := range []string{"new-skill", "demo/new-skill"} {
		if _, err := os.Stat(filepath.Join(outside, path)); !os.IsNotExist(err) {
			t.Fatalf("configured root link escaped: %s %v", path, err)
		}
	}
}

func TestWorkspaceSecuritySkillsMetadataListingRejectsLink(t *testing.T) {
	s, root, outside := skillsSecurityFixture(t)
	secret := filepath.Join(outside, "SKILL.md")
	workspaceSecurityFile(t, secret, "---\nname: demo\ndescription: outside-private-content\n---\nbody\n")
	if err := os.Mkdir(filepath.Join(root, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "demo/SKILL.md")); err != nil {
		t.Fatal(err)
	}
	rec := skillsSecurityCall(t, s.fsListSkills, "GET", "", "", nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "outside-private-content") {
		t.Fatalf("metadata loader read outside skills: %d %s", rec.Code, rec.Body)
	}
}

func TestWorkspaceSecuritySkillsUploadPinsRootDuringRename(t *testing.T) {
	s, root, outside := skillsSecurityFixture(t)
	req := skillsSecurityZipRequest(t, "demo", false)
	req.Body = &workspaceSecuritySwapBody{ReadCloser: req.Body, swap: func() {
		workspaceSecuritySwapDirectory(t, root, outside)
	}}
	rec := httptest.NewRecorder()
	s.fsUploadSkill(rec, req)
	if rec.Code != 201 {
		t.Fatalf("pinned upload=%d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(outside, "demo")); !os.IsNotExist(err) {
		t.Fatalf("upload followed the replaced root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root+"-held", "demo/SKILL.md")); err != nil {
		t.Fatalf("upload did not use the opened root: %v", err)
	}
}

func TestWorkspaceSecuritySkillsMetadataMatchesSDK(t *testing.T) {
	root := t.TempDir()
	for i, mcps := range []string{"mcps: 'one, two'", "mcps: [one, two]", "mcps:\n  - one\n  - two", "mcp: 'one, two'"} {
		data := []byte("---\nname: demo\ndescription: 'inside: quoted description'\nlicense: MIT\ncompatibility: Linux\n" + mcps + "\n---\nbody\n")
		dir := filepath.Join(root, fmt.Sprintf("case-%d", i))
		workspaceSecurityFile(t, filepath.Join(dir, "SKILL.md"), string(data))
		reg, err := skill.LoadDir(dir)
		if err != nil || len(reg.List()) != 1 {
			t.Fatalf("SDK fixture: %v", err)
		}
		want := reg.List()[0]
		got, err := parseSkillMetadata(data)
		if err != nil || got.Name != want.Name || got.Description != want.Description || got.License != want.License ||
			got.Compatibility != want.Compatibility || strings.Join(got.MCPs, "|") != strings.Join(want.MCPs, "|") {
			t.Fatalf("metadata mismatch: got=%+v want=%+v err=%v", got, want, err)
		}
	}
}

func TestWorkspaceSecuritySkillsConcurrentSymlinkReplacement(t *testing.T) {
	s, root, outside := skillsSecurityFixture(t)
	const outsideMD = "---\nname: outside\ndescription: outside-private-content\n---\noutside-private-content\n"
	workspaceSecurityFile(t, filepath.Join(root, "demo/inside/SKILL.md"), "---\nname: demo\ndescription: inside\n---\ninside body\n")
	workspaceSecurityFile(t, filepath.Join(outside, "SKILL.md"), outsideMD)
	for _, name := range []string{"read.txt", "write.txt", "delete.txt"} {
		workspaceSecurityFile(t, filepath.Join(root, "demo/inside", name), "inside")
		workspaceSecurityFile(t, filepath.Join(outside, name), "outside-private-content")
	}
	link := filepath.Join(root, "demo/switch")
	if err := os.Symlink("inside", link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("switch/SKILL.md", filepath.Join(root, "demo/SKILL.md")); err != nil {
		t.Fatal(err)
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	failed := make(chan error, 1)
	var transitions atomic.Int64
	go func() {
		defer close(stopped)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			target := "inside"
			if i%2 == 0 {
				target = "../../outside"
			}
			next := filepath.Join(root, "demo/next-link")
			if err := os.Symlink(target, next); err != nil {
				failed <- err
				return
			}
			if err := os.Rename(next, link); err != nil {
				failed <- err
				return
			}
			transitions.Add(1)
			runtime.Gosched()
		}
	}()
	var stop sync.Once
	stopRace := func() { stop.Do(func() { close(done); <-stopped }) }
	t.Cleanup(stopRace)
	for i := 0; i < 60; i++ {
		for _, item := range []struct {
			handler http.HandlerFunc
			file    string
		}{{s.fsReadFile, "switch/read.txt"}, {s.fsListFiles, ""}, {s.fsListSkills, ""}} {
			rec := skillsSecurityCall(t, item.handler, "GET", "demo", item.file, nil)
			if strings.Contains(rec.Body.String(), "outside-private-content") {
				t.Fatalf("skill read/list followed escaping link: %d %s", rec.Code, rec.Body)
			}
		}
		skillsSecurityCall(t, s.fsUpdateSkillMeta, "PUT", "demo", "", map[string]string{"description": "inside updated"})
		skillsSecurityCall(t, s.fsWriteFile, "PUT", "demo", "switch/write.txt", map[string]string{"content": "inside updated"})
		skillsSecurityCall(t, s.fsCreateDir, "POST", "demo", "", map[string]string{"path": "switch/new-dir"})
		skillsSecurityCall(t, s.fsDeletePath, "DELETE", "demo", "switch/delete.txt", nil)
	}
	stopRace()
	select {
	case err := <-failed:
		t.Fatal(err)
	default:
	}
	if transitions.Load() == 0 {
		t.Fatal("skill symlink replacement race did not run")
	}
	for _, name := range []string{"read.txt", "write.txt", "delete.txt", "SKILL.md"} {
		want := "outside-private-content"
		if name == "SKILL.md" {
			want = outsideMD
		}
		data, err := os.ReadFile(filepath.Join(outside, name))
		if err != nil || string(data) != want {
			t.Fatalf("outside %s changed during skill race: %q %v", name, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "new-dir")); !os.IsNotExist(err) {
		t.Fatalf("skill mkdir escaped during race: %v", err)
	}
}

// This exercises the database-backed whole-skill delete endpoint in the same
// isolated PostgreSQL fixture as the authentication suite. CI rejects any skip.
func TestWorkspaceSecuritySkillsDeleteHTTP(t *testing.T) {
	s, hash := authSessionFixture(t)
	_, root, outside := skillsSecurityFixture(t)
	s.skillDir = root
	workspaceSecurityFile(t, filepath.Join(root, "demo/SKILL.md"), "inside")
	workspaceSecurityFile(t, filepath.Join(outside, "SKILL.md"), "outside-private-content")
	if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	s.requireAuth(http.HandlerFunc(s.fsDeleteSkill)).ServeHTTP(unauthorized, skillsSecurityRequest(t, "DELETE", "alias", "", nil))
	if unauthorized.Code != 401 {
		t.Fatalf("unauthorized delete=%d %s", unauthorized.Code, unauthorized.Body)
	}
	if _, err := os.Lstat(filepath.Join(root, "alias")); err != nil {
		t.Fatalf("unauthorized delete changed the filesystem: %v", err)
	}
	token, err := s.issueJWT(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"demo", "alias"} {
		req := skillsSecurityRequest(t, "DELETE", name, "", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.requireAuth(http.HandlerFunc(s.fsDeleteSkill)).ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("delete %s=%d %s", name, rec.Code, rec.Body)
		}
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("skill path was not deleted: %s %v", name, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(outside, "SKILL.md")); err != nil || string(data) != "outside-private-content" {
		t.Fatalf("whole-skill deletion followed its link: %q %v", data, err)
	}
}
