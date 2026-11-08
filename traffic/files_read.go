package traffic

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

var errTrafficFileUnavailable = errors.New("stored traffic file is unavailable or outside the traffic directory")

// Traffic lives under the configured workspace. Open it through that parent
// handle so a legacy link at traffic/ cannot redirect reads into keys/. Verify
// the opened child itself is the directory entry; all subsequent reads use its
// handle and remain safe when names are replaced concurrently.
func (t *Traffic) openFileRoot() (*os.Root, error) {
	if t == nil || t.dir == "" {
		return nil, errTrafficFileUnavailable
	}
	abs, err := filepath.Abs(t.dir)
	if err != nil {
		return nil, errTrafficFileUnavailable
	}
	parent, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return nil, errTrafficFileUnavailable
	}
	defer parent.Close()
	name := filepath.Base(abs)
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, errTrafficFileUnavailable
	}
	entry, entryErr := parent.Lstat(name)
	opened, openedErr := root.Stat(".")
	if entryErr != nil || openedErr != nil || !entry.IsDir() || !os.SameFile(entry, opened) {
		root.Close()
		return nil, errTrafficFileUnavailable
	}
	return root, nil
}

func readTrafficFile(root *os.Root, name string) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, errTrafficFileUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	entry, entryErr := root.Lstat(name)
	if err != nil || entryErr != nil || !info.Mode().IsRegular() || !entry.Mode().IsRegular() || !os.SameFile(info, entry) {
		return nil, errTrafficFileUnavailable
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, errTrafficFileUnavailable
	}
	return data, nil
}
