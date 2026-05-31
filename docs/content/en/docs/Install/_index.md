---
title: Install
weight: 2
description: Learn how to install GitHub Quick Review (ghqr)
---

## Install on Linux or macOS

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/microsoft/ghqr/main/scripts/install.sh)"
```

Or download the latest release from the [releases page](https://github.com/microsoft/ghqr/releases).

## Install on Windows

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/microsoft/ghqr/main/scripts/install.ps1'))
```

Or download the latest release from the [releases page](https://github.com/microsoft/ghqr/releases).

## Install with Docker

```bash
docker pull ghcr.io/microsoft/ghqr:latest
```

Run a scan using Docker:

```bash
docker run --rm \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  ghcr.io/microsoft/ghqr:latest \
  scan -o my-org
```

## Build from Source

Requires Go 1.24 or higher.

```bash
git clone https://github.com/microsoft/ghqr.git
cd ghqr
make
```

The compiled binary is placed in the `bin/` directory.
