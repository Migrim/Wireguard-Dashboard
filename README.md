# WireGuard Dashboard

A simple, self-hosted web dashboard to manage a WireGuard server on Ubuntu.  
It reads and writes your `/etc/wireguard/<iface>.conf`, keeps a JSON database for issued peers (`/etc/wireguard/peers.json`), and exposes REST endpoints for creating/removing clients, checking service health, and controlling `wg-quick@<iface>` via `systemd`.

<img width="1913" height="723" alt="Bildschirmfoto 2025-10-30 um 16 34 08" src="https://github.com/user-attachments/assets/4a49ab5b-d18f-4a85-b873-0892a9b76079" />

## Features

- Web UI (Flask) on port **8088** by default
- Create WireGuard peers via `/api/users` (auto-assigns IPs from server subnet)
- Download ready-to-use client configs: `/download/<name>.conf`
- Start/stop/restart WireGuard service over the web
- Shows live + issued peers (`wg show <iface> dump` + `peers.json`)
- UFW port check + local listening check

## Requirements

- Ubuntu (preffered)
- Python 3.10+
- `sudo` without password for selected commands for the user running the app
- A running interface, e.g. `/etc/wireguard/wg0.conf` with `wg-quick@wg0` enabled

## Quickstart

```bash
# 1) clone your repo
git clone https://github.com/yourname/Wireguard-Dashboard.git /opt/WireGuard-Dashboard
cd /opt/WireGuard-Dashboard

# 2) create venv
python3 -m venv .venv
source .venv/bin/activate
pip install flask gunicorn

# 3) run (dev)
export APP_PORT=8088
export WG_IFACE=wg0
python app.py
```

Now open: **http://server-ip:8088/**

## Running with systemd (example)

```ini
[Unit]
Description=WireGuard Dashboard
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/WireGuard-Dashboard
Environment="APP_PORT=8088"
Environment="WG_IFACE=wg0"
ExecStart=/opt/WireGuard-Dashboard/.venv/bin/gunicorn -w 2 -b 0.0.0.0:8088 app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp wg-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wg-dashboard
```

## Sudo rules (important)

The app calls things like:

- `/usr/bin/systemctl start|stop|restart wg-quick@wg0`
- `/usr/bin/wg show wg0 dump`
- `/usr/bin/install -m 640 -o root -g www-data ...`
- `cat /etc/wireguard/wg0.conf`

Set a sudoers drop-in (example):

```bash
sudo visudo -f /etc/sudoers.d/wg-dashboard
```

```text
www-data ALL=(root) NOPASSWD: /bin/cat /etc/wireguard/*,   /usr/bin/wg *,   /usr/bin/systemctl * wg-quick@wg0,   /usr/bin/install *
```

Adjust paths/interfaces as needed.

## API overview

- `GET /api/status` – overall state, issued + live clients
- `GET /api/users` – list issued + live
- `POST /api/users` – create peer  
  body: `{"name": "sebastian"}` (optional: `"ip": "10.8.0.23/32"`)
- `POST /api/users/<name>/revoke` – remove peer from wg + conf
- `GET /download/<name>.conf` – download client file
- `POST /api/service` – `{ "action": "start|stop|restart|enable|disable|reload" }`

## Environment variables

- `APP_PORT` (default: `8088`)
- `WG_IFACE` (default: `wg0`)
- `WG_DIR` (default: `/etc/wireguard`)
- `WG_CONF` (default: `/etc/wireguard/<WG_IFACE>.conf`)
- `WG_PORT` (default: `51820`)
- `SERVER_ADDR` (default: `10.8.0.1/24`)
- `SUDO_BIN` (default: `/usr/bin/sudo`)

## Notes

- The dashboard updates `peers.json` and the WireGuard config in sync.
- Client IPs are auto-picked from the server subnet if you don’t provide one.
- Make sure your `wg0.conf` is group-readable by `www-data` or use the provided sudo rules.
