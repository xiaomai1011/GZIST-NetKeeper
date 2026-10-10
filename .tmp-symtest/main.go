package main

import (
	"fmt"
	"os"
)

func main() {
	dir, _ := os.MkdirTemp("", "symtest")
	defer os.RemoveAll(dir)
	os.WriteFile(dir+"/app.exe", []byte("x"), 0600)
	if err := os.Symlink(dir+"/app.exe", dir+"/link.txt"); err != nil {
		fmt.Println("Symlink failed:", err)
		return
	}
	fmt.Println("symlink created")

	// plain Lstat
	if info, err := os.Lstat(dir + "/link.txt"); err == nil {
		fmt.Printf("os.Lstat: mode=%v isSymlink=%v\n", info.Mode(), info.Mode()&os.ModeSymlink != 0)
	}

	// OpenRoot Lstat (what feedcheck uses)
	root, err := os.OpenRoot(dir)
	if err != nil {
		fmt.Println("OpenRoot failed:", err)
		return
	}
	defer root.Close()
	if info, err := root.Lstat("link.txt"); err == nil {
		fmt.Printf("root.Lstat: mode=%v isRegular=%v isSymlink=%v\n", info.Mode(), info.Mode().IsRegular(), info.Mode()&os.ModeSymlink != 0)
	} else {
		fmt.Println("root.Lstat failed:", err)
	}

	// and ReadDir through the root
	d, _ := root.Open(".")
	entries, _ := d.ReadDir(-1)
	for _, e := range entries {
		fmt.Printf("ReadDir: %s isDir=%v type=%v\n", e.Name(), e.IsDir(), e.Type())
	}
}
