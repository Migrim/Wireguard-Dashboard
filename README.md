# WG-Quick

https://one-auth.net/docs/wg-quick

<img width="4074" height="2808" alt="WG-Quick" src="https://github.com/user-attachments/assets/a1ca94f2-4891-4675-a5c4-8ec8c57d0af5" />

## Docker

```sh
docker compose up -d --build
```

Without compose, the equivalent `docker run` is:

```sh
docker build -t wg-dashboard .
docker run -d --name wg-dashboard \
  --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -p 8088:8088 -p 51820:51820/udp \
  -v wg_data:/etc/wireguard \
  --restart unless-stopped \
  wg-dashboard
```

`--cap-add NET_ADMIN` is mandatory — without it WireGuard cannot create interfaces, and the container exits immediately with instructions (this also means GUI "Run" buttons like Docker Desktop's won't work; start it from the CLI or with compose).

The dashboard is served on `http://localhost:8088`, WireGuard listens on UDP 51820. All state (server keys, `wg0.conf`, peers, dashboard password, session secret) lives in the `wg_data` volume, so the container itself is disposable. Configuration is done via the environment variables in [docker-compose.yml](docker-compose.yml); if you change `WG_PORT` or `APP_PORT`, adjust the port mappings to match. On CGNAT/DS-Lite lines set `SERVER_PUBLIC_IP` or use the built-in DynDNS support.

The container needs `NET_ADMIN` and the two `sysctls` from the compose file — WireGuard runs inside the container's network namespace (requires kernel 5.6+ on the host, which includes Docker Desktop). Since there is no systemd in the container, `systemctl`/`journalctl` calls are handled by small shims in [docker/](docker/) that drive `wg-quick` directly; the in-app updater does not apply — update by rebuilding the image.
