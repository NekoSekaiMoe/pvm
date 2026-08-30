# --- build arg: WEBUI_PREBUILT=1 skips the Node/pnpm stage when CI already
# ran `npm run generate` (webui/.output committed as an artifact).
ARG WEBUI_PREBUILT=0

# ---------- Stage 1: WebUI (skippable) ----------
FROM golang:1.23 AS webui
ARG WEBUI_PREBUILT
RUN if [ "$WEBUI_PREBUILT" = "1" ]; then echo "webui prebuilt, skipping"; exit 0; fi; \
    corepack enable && corepack prepare pnpm@latest --activate
COPY webui/ /src/webui/
RUN if [ "$WEBUI_PREBUILT" != "1" ]; then \
      cd /src/webui && pnpm install --frozen-lockfile || pnpm install; \
      cd /src/webui && pnpm run generate; \
    fi

# ---------- Stage 2: Go build ----------
FROM golang:1.23 AS build
ARG WEBUI_PREBUILT
WORKDIR /src
# Cached module download first.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pull in the WebUI output: either from stage 1 or the copy from CI.
RUN --mount=type=bind,from=webui,source=/src/webui,target=/stage-webui \
    if [ -d /stage-webui/.output ]; then cp -r /stage-webui/.output /src/webui/.output; fi
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.buildVersion=${VERSION:-dev}" \
      -o /out/agentpvm ./cmd/agentpvm && \
    CGO_ENABLED=0 go build -trimpath -o /out/umlctl ./cmd/umlctl

# ---------- Stage 3: runtime ----------
# debian-slim rather than distroless: the compose healthcheck needs wget,
# and operator debugging benefits from a minimal shell. Swap the FROM line to
# gcr.io/distroless/base-debian12:nonroot (and drop the wget healthcheck in
# docker-compose.yml) for a smaller, shell-free image.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/pvm --shell /usr/sbin/nologin pvm
COPY --from=build /out/agentpvm /usr/local/bin/agentpvm
COPY --from=build /out/umlctl   /usr/local/bin/umlctl
WORKDIR /var/lib/pvm
USER pvm
EXPOSE 8080 3000 49982 49983
ENTRYPOINT ["/usr/local/bin/agentpvm"]
CMD ["api", "-port", "8080"]
