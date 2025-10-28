# TornadoAI MCP Server

The TornadoAI Mission Control Platform (MCP) server streamlines red teaming and vulnerability assessment 
operations. It provides orchestrated control over scanning campaigns, dynamic tasking, reporting workflows, 
and integrations with a curated toolset covering the OWASP Top 10 (web and mobile) and SANS Top 25.

## Features

- **Vulnerability-driven scans** – Define targets, desired vulnerability classes, runtime thresholds, and
  fine-grained tool overrides.
- **Lifecycle management** – Schedule, start, pause, resume, and cancel scans while editing draft
  configurations safely.
- **Dynamic tasking** – Add, modify, or remove scan tasks at any time, including while a scan is running.
- **Integrated tooling** – Ready-to-run open source and commercial tools spanning network discovery,
  web fuzzing, mobile reverse engineering, and iOS testing workflows.
- **Custom reporting** – Compose Markdown-based reports with selectable sections, inline editing support,
  image placeholders, and export-ready Markdown generation.

## Getting Started

### Prerequisites

- Docker Engine 24+
- (Optional) Python 3.11+ for local development without Docker.

#### Windows-specific setup

The Dockerfile targets the Linux engine. On Windows you must run Docker Desktop and
ensure the **Docker Desktop Backend Service** is active so that the
`//./pipe/dockerDesktopLinuxEngine` named pipe is available. If you encounter an
error such as `The system cannot find the file specified` while running
`docker build`, take the following steps:

1. Launch Docker Desktop and wait for the whale icon to report that the engine is
   running.
2. Open an elevated PowerShell window and enable the WSL 2 backend (requires a
   system restart the first time):
   ```powershell
   wsl --install
   wsl --set-default-version 2
   ```
3. Restart Docker Desktop so that it reconnects to the Linux engine.
4. Verify connectivity from PowerShell:
   ```powershell
   docker info
   docker version
   ```
5. Re-run the build inside the repository directory:
   ```powershell
   docker build -t tornadoai-mcp .
   ```

If the command still fails, confirm that virtualization is enabled in the BIOS and
that security software is not blocking the Docker named pipe.

### Build and Run with Docker

The container image is built on top of `kalilinux/kali-rolling` so you retain the full Kali userland
while layering the MCP server and assessment tooling on top.

```bash
docker build --no-cache -t tornadoai-mcp .
docker run --rm --name tornadoai-mcp-container -p 8000:8000 -v "$PWD"/data:/opt/tornadoai/data tornadoai-mcp
```

> **Why `--no-cache`?**
>
> Earlier revisions of the Dockerfile attempted to install `mobsf`, `frida-tools`, and `objection` from the
> Kali repositories. Those packages are not published in the default `kali-rolling` apt sources, so cached
> build layers can continue to fail with `E: Unable to locate package ...`. Building with `--no-cache`
> forces Docker to pick up the current instructions that install those tools via `pip` and git instead.

> **Mirror troubleshooting**
>
> If you still encounter `Unable to locate package` errors after pulling the latest Dockerfile, confirm
> that the build host can reach `http.kali.org`. The Dockerfile now rewrites `/etc/apt/sources.list` to
> point directly at the official mirror so intermittent geo-IP redirects do not break the build. When
> running outside of Docker (or with a proxy), mirror issues can be diagnosed with:
>
> ```bash
> docker run --rm kalilinux/kali-rolling bash -lc "cat /etc/apt/sources.list && apt-get update"
> ```
>
> Substitute your preferred mirror if local policies require it.

> **Windows PowerShell**
>
> PowerShell does not concatenate paths the same way as POSIX shells. The literal string
> `"$PWD"/data` is treated as a division operation, which results in Docker receiving an empty
> image reference and emitting the `invalid reference format` error. Use `Join-Path` (or an explicit
> variable) to build the bind mount instead:
>
> ```powershell
> $workdir = (Get-Location).Path
> docker run --rm -p 8000:8000 -v (Join-Path $workdir 'data')+':/opt/tornadoai/data' tornadoai-mcp
> ```
>
> Alternatively, create the host path with backslashes directly:
>
> ```powershell
> $workdir = (Get-Location).Path
> docker run --rm -p 8000:8000 -v "$workdir\data:/opt/tornadoai/data" tornadoai-mcp
> ```

The API is now available at `http://localhost:8000`. Interactive documentation is provided via the
[FastAPI Swagger UI](http://localhost:8000/docs) and ReDoc (`/redoc`).

#### Verify bundled tooling

Once the container is running, you can exec into it to confirm that key tools—such as MobSF, Frida, and
Objection—are available alongside the broader Kali arsenal:

```bash
docker exec -it tornadoai-mcp-container bash
which frida
objection --help
ls /opt/tools/mobsf
```

MobSF is installed at `/opt/tools/mobsf` with its Python dependencies resolved during the Docker build,
allowing the framework to be launched immediately when needed.

### Local Development

1. Create a Python virtual environment and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Start the API server:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Example Workflows

- **Create a scan** with a 2 hour duration focusing on OWASP A03 Injection findings:
  ```bash
  http POST :8000/scans \
    name="Web App Injection Sweep" \
    target="https://target.example" \
    vulnerability_classes:='["OWASP_A03_INJECTION"]' \
    duration=7200
  ```
- **Add a dynamic task** during execution:
  ```bash
  http POST :8000/scans/{scan_id}/tasks name="SQLMap Deep Scan" tool=sqlmap \
    parameters:='{"level": "5", "risk": "3"}'
  ```
- **Generate a report** and retrieve Markdown:
  ```bash
  http POST :8000/reports scan_id={scan_id} title="Q2 Assessment"
  http GET :8000/reports/{report_id}/markdown
  ```

## Security Tooling Inventory

The Docker image pre-installs a comprehensive set of offensive security utilities, including but not
limited to:

- `nmap`, `masscan` for network reconnaissance
- `nuclei`, `sqlmap`, `whatweb`, `dirb` for web vulnerability discovery
- `ffuf`, `wfuzz` for fuzzing
- `jadx`, `apktool`, `MobSF`, `reflutter`, `frida-tools`, `objection` for mobile reverse engineering and
  dynamic analysis
- iOS support via `libimobiledevice-utils`, `ifuse`, `ideviceinstaller`, `idb-companion`

> **Note**
>
> Kali packages exist for most tools, but some (such as MobSF, Frida, and Objection) are pulled in via
> Python packages or git clones during the Docker build because they are not available as apt packages.
> The image places MobSF under `/opt/tools/mobsf` for convenience, while `frida-tools`, `objection`,
> and `reflutter` are exposed through the global Python environment.

Extend the `app/tooling.py` catalog or the Dockerfile to integrate bespoke tooling required by your
engagement methodology.

## Reporting Customization

Reports are composed of Markdown sections with the following default structure:

1. Title
2. Index
3. Executive Summary
4. Scope
5. Detailed Vulnerabilities (step-by-step PoC)

Sections can be toggled on/off, reordered, or augmented with images and tables to build executive-ready
artifacts. Use the `/reports/{id}` endpoints to iteratively update report content, and the
`/reports/{id}/markdown` endpoint to export consolidated Markdown for further styling.

## Extending the Platform

- Implement persistent storage (PostgreSQL, Redis) by replacing the in-memory stores located in
  `app/store.py`.
- Connect real tool runners or message queues in `app/main.py` where scan status transitions occur.
- Embed authentication and RBAC around the FastAPI application using dependencies or API gateways.

## License

Distributed under the MIT License. See `LICENSE` (to be supplied) for details.
