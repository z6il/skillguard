package lock

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestHashAndCompare(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("v1"), 0o644)
	os.WriteFile(filepath.Join(root, "keep.md"), []byte("same"), 0o644)
	os.WriteFile(filepath.Join(root, "gone.md"), []byte("bye"), 0o644)
	os.WriteFile(filepath.Join(root, "photo.png"), []byte("not scanned"), 0o644)

	before, err := Hash(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 3 {
		t.Fatalf("hashed %d files, want 3", len(before))
	}

	os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("v2"), 0o644)
	os.Remove(filepath.Join(root, "gone.md"))
	os.WriteFile(filepath.Join(root, "new.sh"), []byte("echo hi"), 0o644)
	after, _ := Hash(root)

	c := Compare(before, after)
	want := Change{Added: []string{"new.sh"}, Removed: []string{"gone.md"}, Modified: []string{"SKILL.md"}}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v, want %+v", c, want)
	}
	if !Compare(after, after).Empty() {
		t.Error("identical hashes should be empty")
	}
}

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "skillguard.lock")
	f, _ := Load(p)
	f.Put("x", map[string]string{"a": "1"})
	if err := f.Save(p); err != nil {
		t.Fatal(err)
	}
	g, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if g.Targets["x"].Files["a"] != "1" {
		t.Errorf("round trip lost data: %+v", g.Targets["x"])
	}
}
