package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to an open work-dir handle, including when a path contains a symlink
// or a directory is renamed concurrently. All routes sit behind requireAuth.

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

// workspacePath normalizes the UI's root-relative spelling. This is input
// validation, not the filesystem security boundary: every operation below must
// use os.Root instead of reopening an absolute path after a check.
func workspacePath(value string) (string, bool) {
	rel := filepath.Clean(strings.TrimPrefix(strings.TrimSpace(value), "/"))
	return rel, filepath.IsLocal(rel) && !strings.ContainsRune(rel, 0)
}

func workspaceDisplayPath(rel string) string {
	if rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

func (s *Server) openWorkspace(w http.ResponseWriter, value string) (*os.Root, string, bool) {
	rel, ok := workspacePath(value)
	if !ok {
		writeErr(w, 400, "invalid path")
		return nil, "", false
	}
	if s.m == nil || s.m.dir == "" {
		writeErr(w, 503, "Workspace is unavailable")
		return nil, "", false
	}
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 503, "Workspace is unavailable")
		return nil, "", false
	}
	return root, rel, true
}

// Root rejects escaping links and unsafe traversal while performing the
// operation. Never reflect the underlying path (which may name a secret) into
// an HTTP error.
func workspacePathError(w http.ResponseWriter, err error) {
	if os.IsNotExist(err) {
		writeErr(w, 404, "workspace path does not exist")
		return
	}
	writeErr(w, 403, "workspace path is invalid or inaccessible")
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	root, rel, ok := s.openWorkspace(w, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	defer root.Close()
	dir, err := root.Open(rel)
	if err != nil {
		workspacePathError(w, err)
		return
	}
	defer dir.Close()
	fi, err := dir.Stat()
	if err != nil {
		workspacePathError(w, err)
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, "not a directory")
		return
	}
	ents, err := dir.ReadDir(-1)
	if err != nil {
		writeErr(w, 500, "failed to read workspace directory")
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		entryPath := filepath.Join(rel, e.Name())
		info, err := root.Lstat(entryPath)
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  workspaceDisplayPath(entryPath),
			Dir:   info.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// Directories first, each sorted by name.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": workspaceDisplayPath(rel), "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	root, rel, ok := s.openWorkspace(w, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	defer root.Close()
	file, err := root.Open(rel)
	if err != nil {
		workspacePathError(w, err)
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		workspacePathError(w, err)
		return
	}
	if !fi.Mode().IsRegular() {
		writeErr(w, 400, "not a regular file")
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": workspaceDisplayPath(rel), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	// Bound the read itself as well as stat: another writer can grow a file
	// after it was opened.
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceRead+1))
	if err != nil {
		writeErr(w, 500, "failed to read workspace file")
		return
	}
	if len(data) > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": workspaceDisplayPath(rel), "size": len(data), "too_large": true, "binary": true})
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": workspaceDisplayPath(rel), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": workspaceDisplayPath(rel), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	root, rel, ok := s.openWorkspace(w, req.Path)
	if !ok {
		return
	}
	defer root.Close()
	if rel == "." {
		writeErr(w, 400, "invalid path")
		return
	}
	if fi, err := root.Stat(rel); err == nil && fi.IsDir() {
		writeErr(w, 400, "target is a directory")
		return
	}
	if err := root.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		workspacePathError(w, err)
		return
	}
	if err := root.WriteFile(rel, []byte(req.Content), 0o600); err != nil {
		workspacePathError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": workspaceDisplayPath(rel)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	root, rel, ok := s.openWorkspace(w, req.Path)
	if !ok {
		return
	}
	defer root.Close()
	if rel == "." {
		writeErr(w, 400, "invalid path")
		return
	}
	if err := root.MkdirAll(rel, 0o755); err != nil {
		workspacePathError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": workspaceDisplayPath(rel)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	root, rel, ok := s.openWorkspace(w, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	defer root.Close()
	if rel == "." {
		writeErr(w, 400, "cannot delete the workspace root directory")
		return
	}
	// Deleting a link removes that link, including a dangling/escaping link;
	// traversing an escaping parent is still refused by Root.
	if _, err := root.Lstat(rel); err != nil {
		workspacePathError(w, err)
		return
	}
	if err := root.RemoveAll(rel); err != nil {
		workspacePathError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	root, rel, ok := s.openWorkspace(w, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	defer root.Close()
	file, err := root.Open(rel)
	if err != nil {
		workspacePathError(w, err)
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		writeErr(w, 404, "file does not exist")
		return
	}
	name := filepath.Base(rel)
	// RFC 5987 filename* keeps non-ASCII names intact; plain filename is the fallback.
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
	http.ServeContent(w, r, name, fi.ModTime(), file)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	root, dir, ok := s.openWorkspace(w, r.URL.Query().Get("path"))
	if !ok {
		return
	}
	defer root.Close()
	if fi, err := root.Stat(dir); err != nil || !fi.IsDir() {
		writeErr(w, 400, "target directory does not exist")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "failed to parse upload or size limit exceeded: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "missing upload file (form field file)")
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			continue
		}
		dest, err := root.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			workspacePathError(w, err)
			return
		}
		if err := saveUpload(hdr, dest); err != nil {
			writeErr(w, 500, "failed to save workspace file")
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

// dest must have been opened through the workspace's os.Root. Sharing the
// already-open handle prevents chat uploads from reopening a checked path.
func saveUpload(hdr *multipart.FileHeader, dest *os.File) error {
	src, err := hdr.Open()
	if err != nil {
		_ = dest.Close()
		return err
	}
	defer src.Close()
	_, copyErr := io.Copy(dest, src)
	closeErr := dest.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}
