// Package web holds the console's React build (web/ in the repo), built
// into dist/ and committed, so `go build` needs no Node.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Files is the built console, rooted at its index.html.
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
