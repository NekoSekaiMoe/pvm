package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:generate npm run generate
// The embedded path depends on how the package is built:
//   - go build (local):        nuxt writes .output/public in webui/ (gitignored)
//   - bazel (//webui:webui):  the nuxt_generate tree artifact is mapped to
//     .output/public relative to the package root (embedsrcs remap)
//go:embed all:.output/public
var embedFS embed.FS

// GetPublicFS returns a file system for the embedded Nuxt static assets
func GetPublicFS() http.FileSystem {
	fsys, err := fs.Sub(embedFS, ".output/public")
	if err != nil {
		panic(err)
	}
	return http.FS(fsys)
}
