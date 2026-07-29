Error: ./patch_e2b.go:9:6: main redeclared in this block
Error: 	./patch.go:7:6: other declaration of main
Error: ./patch_e2b.go:55:2: declared and not used: startNew
# uml-container/internal/vhost
Error: internal/vhost/backend.go:17:14: assignment mismatch: 2 variables but state.ContainerDir returns 1 value
# uml-container/internal/container [uml-container/internal/container.test]
Error: internal/container/manager_test.go:33:24: cannot use mock (variable of type *mockLauncher) as uml.Launcher value in argument to NewManager: *mockLauncher does not implement uml.Launcher (missing method Start)
Error: internal/container/manager_test.go:68:24: cannot use mock (variable of type *mockLauncher) as uml.Launcher value in argument to NewManager: *mockLauncher does not implement uml.Launcher (missing method Start)
