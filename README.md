# Local S3 Storage (MinIO + Nginx HTTPS)

Automated local S3-compatible storage setup using:
- MinIO (object storage)
- Nginx (HTTPS reverse proxy)
- Docker / Docker Compose (with fallback to `docker run` when Compose transport is broken)

This project includes:
- `setup-storage.ps1` for Windows
- `setup-storage.sh` for Linux/macOS

## Features

- HTTPS-enabled local endpoint
- Domain/URL input (for example: `mystorage.local`)
- Optional LAN access for other computers
- Automatic container cleanup prompt for previously created servers
- Port conflict handling (prefers `443`, can fall back to `8443/9443/10443`)
- Self-signed certificate generation and local trust attempt

## Windows Usage

Docker Desktop is a required prerequisite.  
Install it manually first (do not install from terminal commands):

- Official page: `https://www.docker.com/products/docker-desktop/`
- Direct Windows installer: `https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe`

After installing Docker Desktop, open it once and wait for **Engine running**.

Run in **PowerShell as Administrator**:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

Then run the installer from this repo:

```powershell
.\setup-storage.ps1
```

Script reference:

`https://github.com/keyhan-azarjoo/S3/blob/main/setup-storage.ps1`

One-line run from GitHub (PowerShell):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/keyhan-azarjoo/S3/main/setup-storage.ps1' -OutFile 'setup-storage.ps1'; .\setup-storage.ps1"
```

## Linux/macOS Usage

```bash
chmod +x setup-storage.sh
./setup-storage.sh
```

One-line run from GitHub (curl-style):

```bash
curl -fsSL https://raw.githubusercontent.com/keyhan-azarjoo/S3/main/setup-storage.sh -o setup-storage.sh && chmod +x setup-storage.sh && sudo ./setup-storage.sh
```

## Access URLs

After installation, script output shows:
- Proxy URL (HTTPS): `https://<domain>` or `https://<domain>:<port>`
- LAN URL: `https://<server-lan-ip>` (if enabled)
- MinIO Console direct URL: `http://localhost:<minio-ui-port>`
- MinIO API direct URL: `http://localhost:<minio-api-port>`

Default login:
- Username: `admin`
- Password: `StrongPassword123`

## DNS / Domain Notes

If domain works on server but not on other computers, set DNS properly:
- Add router/internal DNS record: `<domain> -> <server-lan-ip>`
- Or add hosts entry on each client (if you choose per-client setup)

Without DNS mapping, use IP URL directly.

## Known Notes

- If Docker Compose fails with `invalid proto:`, installer automatically falls back to `docker run`.
- If `443` is busy, installer can clean previous managed containers or use alternate HTTPS port.
