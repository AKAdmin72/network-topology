# Network Topology

A web-based network topology visualizer that auto-discovers switches and their
interconnections via SNMP/LLDP. Supports Aruba OSCX, HP ProCurve, MikroTik,
Juniper, and any switch that implements LLDP-MIB.

![screenshot](docs/screenshot.png)

## Features

- Auto-discovery of switch topology via LLDP
- Traffic monitoring (in/out bps, errors) per link
- MAC address table with edge-device detection
- VLAN visibility per switch port
- STP state visualization
- Node classification: switch / router / wifi / other (auto from LLDP caps, manual override)
- View filter by node type
- MAC address search and path tracing
- Basic auth + HTTPS via nginx

## Requirements

- Docker and Docker Compose
- SNMP v2c read access to switches
- SSL certificate (self-signed is fine)

## Quick start

```bash
# 1. Copy example configs
cp .env.example .env
cp config/switches.txt.example config/switches.txt
cp config/nginx.conf.example config/nginx.conf

# 2. Edit .env — set SNMP community string and cert directory
nano .env

# 3. Add your switch IPs
nano config/switches.txt

# 4. Set your domain name in nginx.conf
nano config/nginx.conf

# 5. Create basic-auth password file
htpasswd -c config/htpasswd admin

# 6. Place SSL certificate files in the cert directory (default: ./cert/)
#    cert/server.crt  — certificate or fullchain
#    cert/server.key  — private key

# 7. Start
docker compose up -d
```

The UI is available at `https://your.host:8443`.

## Configuration

### `.env`

| Variable | Default | Description |
|---|---|---|
| `SNMP_COMMUNITY` | `public` | SNMPv2c community string |
| `ARUBA_REST_USER` | _(empty)_ | Aruba OSCX REST API username |
| `ARUBA_REST_PASS` | _(empty)_ | Aruba OSCX REST API password |
| `CERT_DIR` | `./cert` | Directory with `server.crt` / `server.key` |

### `config/config.yml`

| Key | Default | Description |
|---|---|---|
| `poll_interval` | `300` | Seconds between topology polls |
| `concurrency` | `20` | Max parallel SNMP sessions |
| `snmp_timeout` | `10` | SNMP request timeout (seconds) |
| `snmp_retries` | `2` | SNMP retries on failure |

### Aruba OSCX

Set `ARUBA_REST_USER` and `ARUBA_REST_PASS` in `.env`. The poller will use the
REST API for VLAN data, falling back to SNMP for everything else.

Per-switch REST credentials can also be set in `config/config.yml`:

```yaml
switches:
  192.168.1.10:
    rest_user: admin
    rest_pass: secret
```

## Architecture

```
nginx (8443 HTTPS) → FastAPI/uvicorn (8080) → SQLite (/data/topology.db)
                                             → SNMP polling (async)
```

- `app/main.py` — FastAPI application, REST API, SSE events
- `app/poller.py` — async SNMP + Aruba REST poller, topology builder
- `app/db.py` — SQLite schema and queries
- `app/templates/index.html` — single-page UI (vis.js)

## Data persistence

All runtime data lives in a Docker volume (`topology_data`). Nothing sensitive
is stored there — only topology snapshots, traffic history, and node positions.
