package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/traffic"
)

func executionTrafficFixture(t *testing.T) (*traffic.Traffic, string, string) {
	t.Helper()
	_, workspace, outside := workspaceSecurityFixture(t)
	dir := filepath.Join(workspace, "traffic")
	store, err := traffic.Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, dir, outside
}

func TestExecutionBoundaryTrafficBlobRejectsHostLinks(t *testing.T) {
	store, dir, outside := executionTrafficFixture(t)
	hash := strings.Repeat("a", 64)
	secret := filepath.Join(outside, "private")
	workspaceSecurityFile(t, secret, "synthetic-private-key")
	bucket := filepath.Join(dir, "_blobs", "sha256", hash[:2])
	if err := os.MkdirAll(bucket, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(bucket, hash+".bin")); err != nil {
		t.Fatal(err)
	}
	data, _, err := store.BlobRange(hash, 0, 8192)
	if err == nil || len(data) != 0 || strings.Contains(err.Error(), outside) {
		t.Fatalf("blob followed a host link: data=%q err=%v", data, err)
	}
	for _, tool := range store.Tools() {
		if tool.Name() != "traffic_blob" {
			continue
		}
		input, _ := json.Marshal(map[string]string{"hash": hash})
		result, err := tool.Call(t.Context(), input, nil)
		if err != nil || !result.IsError || strings.Contains(result.Flatten(), "synthetic-private-key") {
			t.Fatalf("traffic tool exposed the host file: result=%+v err=%v", result, err)
		}
	}
	// A blob must be a regular stored body, not a link to another private file
	// within traffic/ (for example the capture proxy's CA material).
	privateInside := filepath.Join(dir, "_ca", "private-test")
	workspaceSecurityFile(t, privateInside, "synthetic-private-ca")
	if err := os.Remove(filepath.Join(bucket, hash+".bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../_ca/private-test", filepath.Join(bucket, hash+".bin")); err != nil {
		t.Fatal(err)
	}
	if data, _, err := store.BlobRange(hash, 0, 8192); err == nil || len(data) != 0 {
		t.Fatalf("blob followed a private in-root link: data=%q err=%v", data, err)
	}
}

func TestExecutionBoundaryTrafficLegacyRejectsHostLinks(t *testing.T) {
	store, dir, outside := executionTrafficFixture(t)
	workspaceSecurityFile(t, filepath.Join(outside, "request.http"), "synthetic-private-key")
	workspaceSecurityFile(t, filepath.Join(outside, "response.http"), "synthetic-private-key")
	if err := os.Symlink(outside, filepath.Join(dir, "legacy")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`INSERT INTO exchanges(id, path) VALUES('legacy-link', 'legacy')`); err != nil {
		t.Fatal(err)
	}
	req, resp, err := store.Get("legacy-link")
	if err == nil || req != "" || resp != "" || strings.Contains(err.Error(), outside) {
		t.Fatalf("legacy body followed a host link: request=%q response=%q err=%v", req, resp, err)
	}
	for _, tool := range store.Tools() {
		if tool.Name() != "traffic_get" {
			continue
		}
		result, err := tool.Call(t.Context(), json.RawMessage(`{"id":"legacy-link"}`), nil)
		if err != nil || !result.IsError || strings.Contains(result.Flatten(), "synthetic-private-key") {
			t.Fatalf("legacy traffic tool exposed the host file: result=%+v err=%v", result, err)
		}
	}
}

func TestExecutionBoundaryTrafficRejectsReplacedRoot(t *testing.T) {
	store, dir, outside := executionTrafficFixture(t)
	hash := strings.Repeat("a", 64)
	workspaceSecurityFile(t, filepath.Join(outside, "_blobs/sha256/aa", hash+".bin"), "synthetic-private-key")
	workspaceSecuritySwapDirectory(t, dir, outside)
	data, _, err := store.BlobRange(hash, 0, 8192)
	if err == nil || len(data) != 0 {
		t.Fatalf("traffic root replacement escaped: data=%q err=%v", data, err)
	}
}

func TestExecutionBoundaryTrafficBlobConcurrentReplacement(t *testing.T) {
	store, dir, outside := executionTrafficFixture(t)
	hash := strings.Repeat("a", 64)
	secret := filepath.Join(outside, "private")
	workspaceSecurityFile(t, secret, "synthetic-private-key")
	bucket := filepath.Join(dir, "_blobs/sha256/aa")
	workspaceSecurityFile(t, filepath.Join(bucket, "inside.bin"), "stored traffic")
	link := filepath.Join(bucket, hash+".bin")
	if err := os.Symlink("inside.bin", link); err != nil {
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
			target := "inside.bin"
			if i%2 == 0 {
				target = secret
			}
			next := filepath.Join(bucket, "next-link")
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
	for i := 0; i < 120; i++ {
		data, _, err := store.BlobRange(hash, 0, 8192)
		if err == nil && string(data) != "stored traffic" {
			t.Fatalf("concurrent traffic read escaped: %q", data)
		}
	}
	stopRace()
	select {
	case err := <-failed:
		t.Fatal(err)
	default:
	}
	if transitions.Load() == 0 {
		t.Fatal("traffic replacement race did not run")
	}
}
