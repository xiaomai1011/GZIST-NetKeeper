s = open('tools/feedcheck/main_test.go', encoding='utf-8').read()

old = '''		dir := stageFiles(t, map[string]string{"app.exe": "x"})
		switch kind {
		case "symlink":
			if err := os.Symlink(filepath.Join(dir, "app.exe"), filepath.Join(dir, "link.txt")); err != nil {
				t.Fatal(err)
			}'''
new = '''		dir := stageFiles(t, map[string]string{"app.exe": "x"})
		switch kind {
		case "symlink":
			link := filepath.Join(dir, "link.txt")
			if err := os.Symlink(filepath.Join(dir, "app.exe"), link); err != nil {
				if runtime.GOOS == "windows" {
					// needs Administrator or Developer Mode on Windows
					t.Skipf("os.Symlink unavailable: %v", err)
				}
				t.Fatal(err)
			}
			// Some sandboxes materialize symlinks as plain copies; without a
			// real reparse point the "reject symlink" behavior can't be tested.
			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Skipf("environment does not honor symlinks (mode=%v)", info.Mode())
			}'''
assert old in s, "symlink anchor"
s = s.replace(old, new)

old = '''		case "root-symlink", "root-symlink-slash":
			link := filepath.Join(t.TempDir(), "feed")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			dir = link'''
new = '''		case "root-symlink", "root-symlink-slash":
			link := filepath.Join(t.TempDir(), "feed")
			if err := os.Symlink(dir, link); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("os.Symlink unavailable: %v", err)
				}
				t.Fatal(err)
			}
			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Skipf("environment does not honor symlinks (mode=%v)", info.Mode())
			}
			dir = link'''
assert old in s, "root-symlink anchor"
s = s.replace(old, new)

# import runtime
old = '''import (
	"io"'''
new = '''import (
	"io"
	"runtime"'''
assert old in s, "import anchor"
s = s.replace(old, new)

open('tools/feedcheck/main_test.go', 'w', encoding='utf-8', newline='\n').write(s)
print('symlink skips added')
