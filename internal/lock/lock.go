// Package lock records the content hash of every scanned file so later changes show up.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/z6il/skillguard/internal/scan"
)

// File is a lockfile on disk.
type File struct {
	Version int               `json:"version"`
	Targets map[string]*Entry `json:"targets"`
}

// Entry is the approved state of one target.
type Entry struct {
	Locked string            `json:"locked"`
	Files  map[string]string `json:"files"`
}

// Load reads a lockfile. A missing file gives an empty lockfile.
func Load(path string) (*File, error) {
	f := &File{Version: 1, Targets: map[string]*Entry{}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, err
	}
	if f.Targets == nil {
		f.Targets = map[string]*Entry{}
	}
	return f, nil
}

// Save writes the lockfile with stable formatting.
func (f *File) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Hash records every file under root that skillguard would scan.
func Hash(root string) (map[string]string, error) {
	out := map[string]string{}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		h, err := hashFile(root)
		if err != nil {
			return nil, err
		}
		out[filepath.Base(root)] = h
		return out, nil
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && scan.Skipped(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || scan.KindOf(p) == "" {
			return nil
		}
		h, err := hashFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = h
		return nil
	})
	return out, err
}

func hashFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Put stores the current hashes for a target.
func (f *File) Put(key string, files map[string]string) {
	f.Targets[key] = &Entry{Locked: time.Now().UTC().Format(time.RFC3339), Files: files}
}

// Change describes how a target differs from its lockfile entry.
type Change struct {
	Added, Removed, Modified []string
}

// Empty reports whether nothing changed.
func (c Change) Empty() bool { return len(c.Added)+len(c.Removed)+len(c.Modified) == 0 }

// Compare returns what changed between locked and current hashes.
func Compare(locked, current map[string]string) Change {
	var c Change
	for p, h := range current {
		old, ok := locked[p]
		switch {
		case !ok:
			c.Added = append(c.Added, p)
		case old != h:
			c.Modified = append(c.Modified, p)
		}
	}
	for p := range locked {
		if _, ok := current[p]; !ok {
			c.Removed = append(c.Removed, p)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Removed)
	sort.Strings(c.Modified)
	return c
}
