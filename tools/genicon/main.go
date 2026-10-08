// Command genicon writes resources/icon.png and tray previews.
//
//	go run ./tools/genicon
package main

import (
	"log"
	"os"

	"github.com/zzstar101/GZIST-NetKeeper-MyGo/internal/art"
)

func main() {
	if err := os.MkdirAll("resources", 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("resources/icon.png", art.AppIcon(), 0o644); err != nil {
		log.Fatal(err)
	}
}
