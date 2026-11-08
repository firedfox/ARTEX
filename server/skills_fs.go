package server

import (
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// openSkillFilesystem opens the configured root without following a symlink in
// any component. Checking each child's identity after opening it also rejects a
// directory replaced between OpenRoot and Lstat. Subsequent operations use the
// returned handle, never the checked path. Configured symlink roots must be
// replaced with an explicit directory path by the operator.
func openSkillFilesystem(dir string, create bool) (*os.Root, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, os.ErrInvalid
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	anchor := filepath.VolumeName(abs) + string(os.PathSeparator)
	if abs == anchor {
		return nil, os.ErrPermission
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(abs, anchor), string(os.PathSeparator)) {
		next, openErr := openSkillChild(root, component)
		if os.IsNotExist(openErr) && create {
			if mkdirErr := root.Mkdir(component, 0o755); mkdirErr != nil && !os.IsExist(mkdirErr) {
				root.Close()
				return nil, mkdirErr
			}
			next, openErr = openSkillChild(root, component)
		}
		root.Close()
		if openErr != nil {
			return nil, openErr
		}
		root = next
	}
	return root, nil
}

// A named skill is a real directory, not an alias to another skill or to a host
// directory. Even a concurrent replacement cannot change the opened handle.
func openSkillChild(parent *os.Root, name string) (*os.Root, error) {
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	entry, entryErr := parent.Lstat(name)
	opened, openedErr := child.Stat(".")
	if entryErr != nil || openedErr != nil || !entry.IsDir() || !os.SameFile(entry, opened) {
		child.Close()
		return nil, os.ErrPermission
	}
	return child, nil
}

func skillPathError(w http.ResponseWriter, err error) {
	if os.IsNotExist(err) {
		writeErr(w, http.StatusNotFound, "skill path does not exist")
		return
	}
	writeErr(w, http.StatusForbidden, "skill path is invalid or inaccessible")
}

func (s *Server) openSkills(w http.ResponseWriter, create bool) (*os.Root, bool) {
	root, err := openSkillFilesystem(s.skillDir, create)
	if err != nil {
		skillPathError(w, err)
		return nil, false
	}
	return root, true
}

func (s *Server) openNamedSkill(w http.ResponseWriter, name string) (*os.Root, bool) {
	root, ok := s.openSkills(w, false)
	if !ok {
		return nil, false
	}
	defer root.Close()
	child, err := openSkillChild(root, name)
	if err != nil {
		skillPathError(w, err)
		return nil, false
	}
	return child, true
}

func readSkillFile(root *os.Root, name string) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrPermission
	}
	if info.Size() > maxSkillFileBytes {
		return nil, fmt.Errorf("skill file exceeds the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSkillFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSkillFileBytes {
		return nil, fmt.Errorf("skill file exceeds the size limit")
	}
	return data, nil
}

// WalkDir operates on Root.FS: its directory opens remain confined even if a
// directory is replaced with a symlink between enumeration and recursion.
func walkRootedSkillFiles(root *os.Root) ([]string, error) {
	var entries []string
	err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		if d.IsDir() {
			entries = append(entries, path+"/")
		} else {
			entries = append(entries, path)
		}
		return nil
	})
	return entries, err
}

// Norma's LoadDir accepts only a pathname and reopens files with os.ReadFile.
// HTTP management therefore parses the already-confined bytes in memory. These
// fields and scalar/list MCP forms match Norma's YAML frontmatter format; the
// compatibility test also loads the same fixture with the SDK parser.
type skillMetadata struct {
	Name          string          `yaml:"name"`
	Description   string          `yaml:"description"`
	License       string          `yaml:"license"`
	Compatibility string          `yaml:"compatibility"`
	MCPs          skillStringList `yaml:"mcps"`
	MCP           skillStringList `yaml:"mcp"`
}

type skillStringList []string

func (s *skillStringList) UnmarshalYAML(value *yaml.Node) error {
	var scalar string
	if err := value.Decode(&scalar); err == nil {
		for _, item := range strings.Split(strings.Trim(strings.TrimSpace(scalar), "[]"), ",") {
			if item = strings.TrimSpace(strings.Trim(item, `"' `)); item != "" {
				*s = append(*s, item)
			}
		}
		return nil
	}
	var list []string
	if err := value.Decode(&list); err == nil {
		*s = cleanStrs(list)
	}
	return nil
}

func parseSkillMetadata(data []byte) (skillMetadata, error) {
	text := string(data)
	if !strings.HasPrefix(text, "---") {
		return skillMetadata{}, fmt.Errorf("SKILL.md has no YAML frontmatter")
	}
	rest := strings.TrimLeft(strings.TrimPrefix(text, "---"), "\r\n")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return skillMetadata{}, fmt.Errorf("SKILL.md frontmatter is not closed")
	}
	var meta skillMetadata
	if err := yaml.Unmarshal([]byte(rest[:end]), &meta); err != nil {
		return skillMetadata{}, err
	}
	if meta.MCPs == nil {
		meta.MCPs = meta.MCP
	}
	return meta, nil
}

func verifyRootedSkillFile(root *os.Root, wantName string, wantMCPs []string) error {
	data, err := readSkillFile(root, "SKILL.md")
	if err != nil {
		return fmt.Errorf("failed to read SKILL.md")
	}
	meta, err := parseSkillMetadata(data)
	if err != nil || meta.Name != wantName {
		return fmt.Errorf("frontmatter did not parse correctly; the name fell back to the directory")
	}
	if len(wantMCPs) != len(meta.MCPs) {
		return fmt.Errorf("parsed MCP list does not match the written list")
	}
	for i, value := range wantMCPs {
		if value != meta.MCPs[i] {
			return fmt.Errorf("parsed MCP list does not match the written list")
		}
	}
	return nil
}
