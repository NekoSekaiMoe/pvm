package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:generate npm run generate
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
