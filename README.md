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

```bash
docker build -t tornadoai-mcp .
docker run --rm -p 8000:8000 -v "$PWD"/data:/opt/tornadoai/data tornadoai-mcp
```

The API is now available at `http://localhost:8000`. Interactive documentation is provided via the
[FastAPI Swagger UI](http://localhost:8000/docs) and ReDoc (`/redoc`).

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
