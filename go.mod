module uml-container

go 1.26.5

require (
	github.com/cilium/ebpf v0.22.0
	github.com/google/go-containerregistry v0.21.7
	github.com/labstack/echo/v4 v4.15.4
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.46.0
)

require (
	github.com/docker/cli v29.5.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/iceber/iouring-go v0.0.0-20230403020409-002cfd2e2a90 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/labstack/gommon v0.5.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)

replace github.com/iceber/iouring-go => ./internal/pkg/iouring-go
