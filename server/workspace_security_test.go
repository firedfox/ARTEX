package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func workspaceSecurityFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	base := t.TempDir()
	root, outside := filepath.Join(base, "workspace"), filepath.Join(base, "outside")
	for _, dir := range []string{root, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{m: &Manager{dir: root}}, root, outside
}

func workspaceSecurityFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func workspaceSecurityJSON(t *testing.T, handler http.HandlerFunc, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func workspaceSecurityUpload(target, name, content string) (*http.Request, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(part, content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	req := httptest.NewRequest("POST", target, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, nil
}

func workspaceSecurityDenied(t *testing.T, rec *httptest.ResponseRecorder, outside string) {
	t.Helper()
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("unsafe path response=%d body=%s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), outside) || strings.Contains(rec.Body.String(), "outside-private-content") {
		t.Fatalf("unsafe path response leaked the outside path or content: %s", rec.Body)
	}
}

func TestWorkspaceSecurityNormalLifecycle(t *testing.T) {
	s, root, _ := workspaceSecurityFixture(t)
	mkdir := workspaceSecurityJSON(t, s.wsMkdir, "POST", "/api/workspace/mkdir", map[string]string{"path": "reports"})
	if mkdir.Code != 200 {
		t.Fatalf("mkdir=%d %s", mkdir.Code, mkdir.Body)
	}
	write := workspaceSecurityJSON(t, s.wsWrite, "POST", "/api/workspace/write", map[string]string{"path": "reports/report.txt", "content": "inside text"})
	if write.Code != 200 {
		t.Fatalf("write=%d %s", write.Code, write.Body)
	}
	read := workspaceSecurityJSON(t, s.wsRead, "GET", "/api/workspace/read?path=reports/report.txt", nil)
	var file struct{ Content string }
	if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &file) != nil || file.Content != "inside text" {
		t.Fatalf("read=%d %s", read.Code, read.Body)
	}
	list := workspaceSecurityJSON(t, s.wsList, "GET", "/api/workspace/list?path=reports", nil)
	var listing struct {
		Path    string
		Entries []wsEntry
	}
	if list.Code != 200 || json.Unmarshal(list.Body.Bytes(), &listing) != nil || len(listing.Entries) != 1 ||
		listing.Path != "reports" || listing.Entries[0].Path != "reports/report.txt" {
		t.Fatalf("list=%d %s", list.Code, list.Body)
	}
	req := httptest.NewRequest("GET", "/api/workspace/download?path=reports/report.txt", nil)
	req.Header.Set("Range", "bytes=0-5")
	download := httptest.NewRecorder()
	s.wsDownload(download, req)
	if download.Code != http.StatusPartialContent || download.Body.String() != "inside" {
		t.Fatalf("download range=%d %s", download.Code, download.Body)
	}
	uploadReq, err := workspaceSecurityUpload("/api/workspace/upload?path=reports", "upload.txt", "normal upload")
	if err != nil {
		t.Fatal(err)
	}
	upload := httptest.NewRecorder()
	s.wsUpload(upload, uploadReq)
	if upload.Code != 200 {
		t.Fatalf("upload=%d %s", upload.Code, upload.Body)
	}
	data, err := os.ReadFile(filepath.Join(root, "reports/upload.txt"))
	if err != nil || string(data) != "normal upload" {
		t.Fatalf("uploaded content=%q err=%v", data, err)
	}
	// Relative symlinks that stay inside the workspace remain usable.
	if err := os.Symlink("reports/report.txt", filepath.Join(root, "inside-link")); err != nil {
		t.Fatal(err)
	}
	read = workspaceSecurityJSON(t, s.wsRead, "GET", "/api/workspace/read?path=inside-link", nil)
	if read.Code != 200 || !strings.Contains(read.Body.String(), "inside text") {
		t.Fatalf("in-root link=%d %s", read.Code, read.Body)
	}
	deleted := workspaceSecurityJSON(t, s.wsDelete, "DELETE", "/api/workspace/delete?path=reports", nil)
	if deleted.Code != 200 {
		t.Fatalf("delete=%d %s", deleted.Code, deleted.Body)
	}
	if _, err := os.Stat(filepath.Join(root, "reports")); !os.IsNotExist(err) {
		t.Fatalf("deleted directory still exists: %v", err)
	}
}

func TestWorkspaceSecurityRejectsSymlinkEscapes(t *testing.T) {
	s, root, outside := workspaceSecurityFixture(t)
	secret := filepath.Join(outside, "private.txt")
	workspaceSecurityFile(t, secret, "outside-private-content")
	for name, target := range map[string]string{
		"absolute-dir": outside,
		"relative-dir": "../outside",
		"leaf-link":    secret,
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, prefix := range []string{"absolute-dir", "relative-dir"} {
		t.Run(prefix, func(t *testing.T) {
			workspaceSecurityDenied(t, workspaceSecurityJSON(t, s.wsList, "GET", "/api/workspace/list?path="+prefix, nil), outside)
			for _, item := range []struct {
				handler http.HandlerFunc
				name    string
			}{{s.wsRead, "read"}, {s.wsDownload, "download"}} {
				workspaceSecurityDenied(t, workspaceSecurityJSON(t, item.handler, "GET", "/api/workspace/"+item.name+"?path="+prefix+"/private.txt", nil), outside)
			}
			workspaceSecurityDenied(t, workspaceSecurityJSON(t, s.wsWrite, "POST", "/api/workspace/write",
				map[string]string{"path": prefix + "/private.txt", "content": "must stay inside"}), outside)
			workspaceSecurityDenied(t, workspaceSecurityJSON(t, s.wsMkdir, "POST", "/api/workspace/mkdir",
				map[string]string{"path": prefix + "/new-dir"}), outside)
			workspaceSecurityDenied(t, workspaceSecurityJSON(t, s.wsDelete, "DELETE", "/api/workspace/delete?path="+prefix+"/private.txt", nil), outside)
			req, err := workspaceSecurityUpload("/api/workspace/upload?path="+prefix, "private.txt", "must stay inside")
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			s.wsUpload(rec, req)
			workspaceSecurityDenied(t, rec, outside)
		})
	}
	for _, item := range []struct {
		handler http.HandlerFunc
		name    string
	}{{s.wsRead, "read"}, {s.wsDownload, "download"}} {
		workspaceSecurityDenied(t, workspaceSecurityJSON(t, item.handler, "GET", "/api/workspace/"+item.name+"?path=leaf-link", nil), outside)
	}
	workspaceSecurityDenied(t, workspaceSecurityJSON(t, s.wsWrite, "POST", "/api/workspace/write",
		map[string]string{"path": "leaf-link", "content": "must stay inside"}), outside)
	req, err := workspaceSecurityUpload("/api/workspace/upload", "leaf-link", "must stay inside")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.wsUpload(rec, req)
	workspaceSecurityDenied(t, rec, outside)
	// Removing a bad link itself is safe; it must not remove its target.
	for _, name := range []string{"absolute-dir", "leaf-link"} {
		rec = workspaceSecurityJSON(t, s.wsDelete, "DELETE", "/api/workspace/delete?path="+name, nil)
		if rec.Code != 200 {
			t.Fatalf("unlink=%d %s", rec.Code, rec.Body)
		}
	}
	data, err := os.ReadFile(secret)
	if err != nil || string(data) != "outside-private-content" {
		t.Fatalf("outside file changed: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "new-dir")); !os.IsNotExist(err) {
		t.Fatalf("created outside the workspace: %v", err)
	}
}

func TestWorkspaceSecurityRejectsRootMutationAndTraversal(t *testing.T) {
	s, root, _ := workspaceSecurityFixture(t)
	for _, path := range []string{"", ".", "/", "folder/..", "../outside", "folder/../../outside", "bad\x00path"} {
		for _, item := range []struct {
			handler http.HandlerFunc
			name    string
		}{{s.wsWrite, "write"}, {s.wsMkdir, "mkdir"}} {
			rec := workspaceSecurityJSON(t, item.handler, "POST", "/api/workspace/"+item.name,
				map[string]string{"path": path, "content": "must not replace the root"})
			if rec.Code != 400 {
				t.Fatalf("%s(%q)=%d %s", item.name, path, rec.Code, rec.Body)
			}
		}
		rec := workspaceSecurityJSON(t, s.wsDelete, "DELETE", "/api/workspace/delete?path="+url.QueryEscape(path), nil)
		if rec.Code != 400 {
			t.Fatalf("delete(%q)=%d %s", path, rec.Code, rec.Body)
		}
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Fatalf("workspace root changed: %v", err)
	}
}

// This reader swaps the already-validated directory immediately before the
// multipart parser reads the first body byte, making the TOCTOU deterministic.
type workspaceSecuritySwapBody struct {
	io.ReadCloser
	once sync.Once
	swap func()
}

func (r *workspaceSecuritySwapBody) Read(p []byte) (int, error) {
	r.once.Do(r.swap)
	return r.ReadCloser.Read(p)
}

func workspaceSecuritySwapDirectory(t *testing.T, path, outside string) {
	t.Helper()
	if err := os.Rename(path, path+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceSecurityUploadRejectsDirectorySwap(t *testing.T) {
	s, root, outside := workspaceSecurityFixture(t)
	workspaceSecurityFile(t, filepath.Join(root, "inbox/previous.txt"), "inside")
	req, err := workspaceSecurityUpload("/api/workspace/upload?path=inbox", "new.txt", "must stay inside")
	if err != nil {
		t.Fatal(err)
	}
	req.Body = &workspaceSecuritySwapBody{ReadCloser: req.Body, swap: func() {
		workspaceSecuritySwapDirectory(t, filepath.Join(root, "inbox"), outside)
	}}
	rec := httptest.NewRecorder()
	s.wsUpload(rec, req)
	workspaceSecurityDenied(t, rec, outside)
	if _, err := os.Stat(filepath.Join(outside, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("upload escaped after directory swap: %v", err)
	}
}

type workspaceSecuritySwapWriter struct {
	*httptest.ResponseRecorder
	once sync.Once
	swap func()
}

func (w *workspaceSecuritySwapWriter) Header() http.Header {
	w.once.Do(w.swap)
	return w.ResponseRecorder.Header()
}

func TestWorkspaceSecurityDownloadUsesOpenedFile(t *testing.T) {
	s, root, outside := workspaceSecurityFixture(t)
	workspaceSecurityFile(t, filepath.Join(root, "inbox/report.txt"), "inside content")
	workspaceSecurityFile(t, filepath.Join(outside, "report.txt"), "outside-private-content")
	rec := httptest.NewRecorder()
	writer := &workspaceSecuritySwapWriter{ResponseRecorder: rec, swap: func() {
		workspaceSecuritySwapDirectory(t, filepath.Join(root, "inbox"), outside)
	}}
	s.wsDownload(writer, httptest.NewRequest("GET", "/api/workspace/download?path=inbox/report.txt", nil))
	if rec.Code != 200 || rec.Body.String() != "inside content" {
		t.Fatalf("download reopened the swapped name: %d %s", rec.Code, rec.Body)
	}
}

func TestWorkspaceSecurityConcurrentSymlinkReplacement(t *testing.T) {
	s, root, outside := workspaceSecurityFixture(t)
	for _, name := range []string{"read.txt", "write.txt", "upload.txt", "delete.txt"} {
		workspaceSecurityFile(t, filepath.Join(root, "inside", name), "inside content")
		workspaceSecurityFile(t, filepath.Join(outside, name), "outside-private-content")
	}
	workspaceSecurityFile(t, filepath.Join(outside, "outside-only-name"), "outside-private-content")
	link := filepath.Join(root, "switch")
	if err := os.Symlink("inside", link); err != nil {
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
				target = "../outside"
			}
			next := filepath.Join(root, "next-link")
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
	for i := 0; i < 80; i++ {
		for _, item := range []struct {
			handler http.HandlerFunc
			name    string
			path    string
		}{{s.wsRead, "read", "switch/read.txt"}, {s.wsDownload, "download", "switch/read.txt"}, {s.wsList, "list", "switch"}} {
			rec := workspaceSecurityJSON(t, item.handler, "GET", "/api/workspace/"+item.name+"?path="+item.path, nil)
			if strings.Contains(rec.Body.String(), "outside-private-content") || strings.Contains(rec.Body.String(), "outside-only-name") {
				t.Fatalf("%s followed the escaping link: %d %s", item.name, rec.Code, rec.Body)
			}
		}
		workspaceSecurityJSON(t, s.wsWrite, "POST", "/api/workspace/write", map[string]string{"path": "switch/write.txt", "content": "inside updated"})
		workspaceSecurityJSON(t, s.wsMkdir, "POST", "/api/workspace/mkdir", map[string]string{"path": "switch/new-dir"})
		workspaceSecurityJSON(t, s.wsDelete, "DELETE", "/api/workspace/delete?path=switch/delete.txt", nil)
		req, err := workspaceSecurityUpload("/api/workspace/upload?path=switch", "upload.txt", "inside upload")
		if err != nil {
			t.Fatal(err)
		}
		s.wsUpload(httptest.NewRecorder(), req)
	}
	stopRace()
	select {
	case err := <-failed:
		t.Fatal(err)
	default:
	}
	if transitions.Load() == 0 {
		t.Fatal("symlink replacement race did not run")
	}
	for _, name := range []string{"read.txt", "write.txt", "upload.txt", "delete.txt"} {
		data, err := os.ReadFile(filepath.Join(outside, name))
		if err != nil || string(data) != "outside-private-content" {
			t.Fatalf("outside %s changed during race: %q %v", name, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "new-dir")); !os.IsNotExist(err) {
		t.Fatalf("mkdir escaped during race: %v", err)
	}
}

func TestChatUploadSecurityRejectsDirectorySwap(t *testing.T) {
	s, root, outside := workspaceSecurityFixture(t)
	req, err := workspaceSecurityUpload("/api/chat/upload?scope=session&id=session-one", "new.txt", "must stay inside")
	if err != nil {
		t.Fatal(err)
	}
	req.Body = &workspaceSecuritySwapBody{ReadCloser: req.Body, swap: func() {
		workspaceSecuritySwapDirectory(t, filepath.Join(root, "sessions/session-one/uploads"), outside)
	}}
	rec := httptest.NewRecorder()
	s.chatUpload(rec, req)
	workspaceSecurityDenied(t, rec, outside)
	if _, err := os.Stat(filepath.Join(outside, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("chat upload escaped after directory swap: %v", err)
	}
}

func TestChatUploadSecurityExistingLinks(t *testing.T) {
	s, root, outside := workspaceSecurityFixture(t)
	if err := os.Symlink(outside, filepath.Join(root, "sessions")); err != nil {
		t.Fatal(err)
	}
	req, err := workspaceSecurityUpload("/api/chat/upload?scope=session&id=one", "new.txt", "inside")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.chatUpload(rec, req)
	workspaceSecurityDenied(t, rec, outside)
	if _, err := os.Stat(filepath.Join(outside, "one")); !os.IsNotExist(err) {
		t.Fatalf("chat directory escaped: %v", err)
	}
	dir := filepath.Join(root, "drafts/stage/uploads")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "must-not-create"), filepath.Join(dir, "new.txt")); err != nil {
		t.Fatal(err)
	}
	req, err = workspaceSecurityUpload("/api/chat/upload?scope=staging&id=stage", "new.txt", "inside")
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.chatUpload(rec, req)
	if rec.Code != 200 {
		t.Fatalf("safe filename fallback=%d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(outside, "must-not-create")); !os.IsNotExist(err) {
		t.Fatalf("chat upload followed dangling destination link: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "new-1.txt"))
	if err != nil || string(data) != "inside" {
		t.Fatalf("safe filename content=%q err=%v", data, err)
	}
}

func TestChatUploadSecurityConcurrentNames(t *testing.T) {
	s, root, _ := workspaceSecurityFixture(t)
	const count = 16
	type result struct {
		attachment chatAttachment
		content    string
		err        error
	}
	results := make(chan result, count)
	for i := 0; i < count; i++ {
		go func() {
			content := fmt.Sprintf("attachment-%02d", i)
			req, err := workspaceSecurityUpload("/api/chat/upload?scope=session&id=parallel", "shared.txt", content)
			if err != nil {
				results <- result{err: err}
				return
			}
			rec := httptest.NewRecorder()
			s.chatUpload(rec, req)
			var payload struct{ Attachments []chatAttachment }
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &payload) != nil || len(payload.Attachments) != 1 {
				results <- result{err: fmt.Errorf("upload=%d %s", rec.Code, rec.Body)}
				return
			}
			results <- result{attachment: payload.Attachments[0], content: content}
		}()
	}
	names := map[string]bool{}
	for i := 0; i < count; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if names[r.attachment.Name] {
			t.Fatalf("concurrent uploads reused filename %q", r.attachment.Name)
		}
		names[r.attachment.Name] = true
		path := filepath.Join(root, "sessions/parallel/uploads", r.attachment.Name)
		data, err := os.ReadFile(path)
		if err != nil || string(data) != r.content {
			t.Fatalf("attachment overwritten: name=%q data=%q expected=%q err=%v", r.attachment.Name, data, r.content, err)
		}
	}
}
