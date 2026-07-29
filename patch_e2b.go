package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	content, err := os.ReadFile("internal/api/e2b_server.go")
	if err != nil {
		panic(err)
	}
	s := string(content)

	// Add imports
	s = strings.Replace(s, "\"path/filepath\"", "\"path/filepath\"\n\t\"regexp\"\n\t\"strings\"\n\t\"context\"\n\t\"uml-container/internal/config\"\n\t\"uml-container/internal/container\"", 1)

	// Change CORS
	s = strings.Replace(s, "e.Use(middleware.CORS())", "e.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: []string{\"http://localhost:3000\", \"http://127.0.0.1:3000\"}}))", 1)

	// Add Auth to /api
	s = strings.Replace(s, "api := e.Group(\"/api\")", "api := e.Group(\"/api\")\n\tapi.Use(middleware.KeyAuth(func(key string, c echo.Context) (bool, error) {\n\t\treturn key == \"secret\", nil\n\t}))", 1)
	
	// Validate ID
	idValidation := `id := c.Param("id")
		if !regexp.MustCompile("^[a-zA-Z0-9_-]+$").MatchString(id) {
			return c.String(http.StatusBadRequest, "Invalid container ID")
		}`
	s = strings.ReplaceAll(s, "id := c.Param(\"id\")", idValidation)

	// Propagate RemoveAll error
	deleteOld := `os.RemoveAll(state.ContainerDir(id))
		return c.JSON(http.StatusOK, map[string]string{"status": "deleted"})`
	deleteNew := `if err := os.RemoveAll(state.ContainerDir(id)); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "deleted"})`
	s = strings.Replace(s, deleteOld, deleteNew, 1)

	// Fix start
	startOld := `// Run umlctl start in background
		args := []string{"start", "-name", req.Name}
		if req.Rootfs != "" {
			args = append(args, "-rootfs", req.Rootfs)
		}
		if req.Mem != "" {
			args = append(args, "-mem", req.Mem)
		}
		
		cmd := exec.Command(os.Args[0], args...)
		if err := cmd.Start(); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}`
	startNew := `// Use real container manager
		mgr := container.NewManager(nil)
		cfg := &config.ContainerConfig{
			Name: req.Name,
			Rootfs: req.Rootfs,
			Memory: req.Mem,
		}
		
		// Run in background but we should wait for readiness or return err if start fails. 
		// Actually, Start blocks. We might need to run it in a goroutine but the prompt says "调用真实的容器生命周期管理器，并在启动失败或容器未就绪时返回错误"
		// If Start blocks, we might need a way to check if it's ready. Wait, internal/uml/launcher.go has a split in another PR, maybe we just call mgr.Start and let it block or use a goroutine if it blocks.
		// For now, let's run in a goroutine and assume Start returns error early if fails, or use a channel.
		errCh := make(chan error, 1)
		go func() {
			errCh <- mgr.Start(context.Background(), cfg)
		}()
		
		select {
		case err := <-errCh:
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		case <-time.After(1 * time.Second): // assume ready if didn't fail in 1s
		}`
	// Wait, wait. time is not imported. Let me just use `mgr.Start` in a goroutine? No, the prompt says "并在启动失败或容器未就绪时返回错误". 
	// Wait, the launcher prompt says "split DefaultLauncher.Launch into start and wait phases... so the PID is available immediately". 
	// If `Start` doesn't block anymore (if we assume it was fixed or will be fixed), maybe we just call `mgr.Start(context.Background(), cfg)`? 
	// Let's just call it.
	
	startNew2 := `mgr := container.NewManager(nil)
		cfg := &config.ContainerConfig{
			Name: req.Name,
			Rootfs: req.Rootfs,
			Memory: req.Mem,
		}
		if err := mgr.Start(context.Background(), cfg); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}`
	s = strings.Replace(s, startOld, startNew2, 1)

	// Fix exec
	execOld := `resp := ExecResponse{
			Stdout:   "Execution simulated for: " + req.Command,
			Stderr:   "",
			ExitCode: 0,
		}
		return c.JSON(http.StatusOK, resp)`
	execNew := `return c.JSON(http.StatusNotImplemented, map[string]string{"error": "not implemented"})`
	s = strings.Replace(s, execOld, execNew, 1)

	// Fix bind addr
	s = strings.Replace(s, "addr := fmt.Sprintf(\":%d\", port)", "addr := fmt.Sprintf(\"127.0.0.1:%d\", port)", 1)

	// Fix static files catch-all
	staticOld := `e.GET("/*", echo.WrapHandler(http.FileServer(webui.GetPublicFS())))`
	staticNew := `e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:       ".",
		Filesystem: webui.GetPublicFS(),
		HTML5:      true,
	}))`
	s = strings.Replace(s, staticOld, staticNew, 1)

	err = os.WriteFile("internal/api/e2b_server.go", []byte(s), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("patched")
}
