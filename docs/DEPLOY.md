# PVM Deployment Guide

Three supported ways to run the PVM controller (`agentpvm`): bare metal with
systemd (recommended), Docker Compose, or fully manual.

- **API server**: `agentpvm api -port 8080` (default 8080)
- **WebUI server**: `agentpvm webui --port 3000` (default 3000)
- **envd compatibility**: ports 49982 (WebSocket version service) and 49983
  (Connect-JSON) when enabled.

The `webui` subcommand serves the embedded Nuxt 3 SPA; build it first with
`make webui` (or `cd webui && npm run generate`) or the server falls back to
serving whatever `webui/.output` contains at build time.

---

## 1. Bare metal with systemd (recommended)

```bash
sudo ./deploy/install.sh
```

`install.sh` is idempotent and does everything below; it never requires
Docker.

1. **Preflight checks**
   - Go 1.22+ toolchain (optional — you may prebuild binaries and drop them
     into `$PREFIX`, default `/usr/local/bin`)
   - ≥ 2 GiB free disk on the filesystem backing `/var/lib`
   - ports 8080 / 3000 free
   - creates the unprivileged `pvm` system user for running the services
2. **Generates `/etc/pvm/pvm.env`** (mode `0600`) with a fresh
   `API_SECRET=$(openssl rand -hex 32)` and the state-root variables. If the
   file already exists it is kept unchanged.
3. **Builds and installs** `agentpvm` and `umlctl` into `$PREFIX`.
4. **Installs systemd units** `agentpvm-api.service` /
   `agentpvm-webui.service` and runs `systemctl daemon-reload` +
   `systemctl enable`.

Then start:

```bash
sudo systemctl start agentpvm-api agentpvm-webui
curl -s http://localhost:8080/healthz
```

Uninstall (keeps `/etc/pvm/pvm.env` and all state under `/var/lib/pvm`):

```bash
sudo ./deploy/install.sh --uninstall
```

Custom prefix: `sudo PREFIX=/opt/pvm ./deploy/install.sh`.

---

## 2. Docker Compose

```bash
cp deploy/pvm.env.example deploy/.env
# edit deploy/.env: API_SECRET=$(openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env build
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
curl -s http://localhost:8080/healthz
```

- Single image, two services: `api` (8080) and `webui` (3000); `webui` waits
  for the `api` healthcheck (`GET /healthz`) before starting.
- All state is bind-mounted at `/var/lib/pvm` — the exact same layout as the
  bare-metal install, so you can migrate between the two.
- If CI already built the WebUI (`webui/.output` present), build with
  `--build-arg WEBUI_PREBUILT=1` to skip the pnpm/Node stage.
- `deploy/install.sh --docker` prints these instructions without needing
  Docker locally.

---

## 3. Manual

```bash
go build -o /usr/local/bin/agentpvm ./cmd/agentpvm
go build -o /usr/local/bin/umlctl   ./cmd/umlctl
make webui                                   # optional: embedded SPA
export API_SECRET="$(openssl rand -hex 32)"
export PVM_STATE_ROOT=/var/lib/pvm/state
export PVM_AUDIT_ROOT=/var/lib/pvm/audit
export PVM_CGROUP_ROOT=/var/lib/pvm/cgroup
agentpvm api -port 8080 &
agentpvm webui --port 3000 &
```

The API **refuses to start without `API_SECRET`** — there is no fallback.

---

## Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `API_SECRET` | **yes** | — | Shared secret for `/api` Bearer auth and E2B `X-API-KEY` auth. |
| `PVM_STATE_ROOT` | no | built-in default | Task/spec lifecycle state (fsjson atomic writes). |
| `PVM_AUDIT_ROOT` | no | built-in default | Tamper-evident audit ledgers. |
| `PVM_CGROUP_ROOT` | no | built-in default | cgroup v2 hierarchy root for tasks. |
| `PVM_VOLUME_ROOT` | no | `PVM_COW_ROOT` | Volume metadata + qcow2 blocks. |
| `PVM_COW_ROOT` | no | built-in default | Block-level CoW engine root. |
| `PVM_KERNEL` | no | `./bin/linux` | UML kernel binary path. |
| `PVM_APPROVAL_WEBHOOK_URL` | no | — | Webhook notified on new approval tickets. |
| `PVM_METRICS_NOAUTH` | no | — | `1` exposes `/metrics` without auth. |

---

## Security recommendations

- **Treat `API_SECRET` like a password**: ≥ 32 random bytes
  (`openssl rand -hex 32`), stored in `/etc/pvm/pvm.env` with mode `0600`
  (never world-readable), rotate periodically, and never commit it.
- **Directory permissions**: `/var/lib/pvm` and every `PVM_*_ROOT` should be
  `0700`, owned by the `pvm` service user. The audit ledger and state
  contain task payloads and possibly secrets.
- **Run unprivileged**: the systemd units default to `User=pvm` with
  `ProtectSystem=strict`, `NoNewPrivileges=true`, and only
  `/var/lib/pvm` writable.
- **`PVM_METRICS_NOAUTH=1`** disables auth on `/metrics` — only enable it on
  a loopback interface or behind a trusted proxy.
- **envd ports (49982/49983) are unauthenticated by design** (E2B
  compatibility); firewall them from anything but the trusted client network.
- Prefer `Restart=on-failure` units over long-running shell loops so crashes
  are visible in `journalctl -u agentpvm-api`.
