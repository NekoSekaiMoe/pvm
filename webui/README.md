# WebUI (`webui/`)

This directory contains the source code for the PVM Web Dashboard, built with **Nuxt 3** and **Vue**.

## Design

The UI utilizes a modern **Glassmorphism** design over a dark mode background, implemented entirely in vanilla CSS (`assets/css/main.css`) for maximum performance and customizability without relying on heavy CSS frameworks.

## Development

To work on the frontend independently:

```bash
cd webui
npm install
npm run dev
```

## Build & Embedding

PVM serves this interface directly from the Go binary. To update the embedded UI:

```bash
cd webui
npm run generate
# This generates static files in .output/public

# Then rebuild the Go binary in the root directory
cd ..
go build ./cmd/umlctl
```

The Go compiler uses the `//go:embed` directive located in `webui/embed.go` to bundle `.output/public` into `umlctl`.
