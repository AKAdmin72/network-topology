# CLAUDE.md — Network Topology

## Stack

- **Backend**: FastAPI + uvicorn (Python 3.12), async SNMP via `snmpbulkwalk`/`snmpget` subprocesses
- **Database**: SQLite at `/data/topology.db` (Docker volume `topology_data`)
- **Frontend**: Single-page app in `app/templates/index.html`, vis.js 9.1.9 for graph
- **Proxy**: nginx with basic auth + HTTPS (port 8443)
- **Runtime**: Docker Compose, `network_mode: host` (required for SNMP to reach switches)

## File structure

```
app/
  main.py          — FastAPI app, all REST endpoints, SSE, polling orchestration
  poller.py        — async SNMP walker, topology builder, port poller
  db.py            — SQLite schema + all queries (no ORM)
  templates/
    index.html     — entire frontend (HTML + CSS + JS, no build step)
config/
  config.yml       — poll_interval, concurrency, snmp_timeout, snmp_retries
  switches.txt     — one switch IP per line (gitignored, use switches.txt.example)
  nginx.conf       — gitignored, use nginx.conf.example
  htpasswd         — gitignored
.env               — SNMP_COMMUNITY, ARUBA_REST_USER, ARUBA_REST_PASS, CERT_DIR (gitignored)
docker-compose.yml
git_commit         — helper script: git add -A && commit && push
```

## Commands

```bash
# Rebuild and restart after any Python or HTML change
docker compose up --build -d

# Logs
docker compose logs -f topology

# Commit and push
./git_commit "message"
```

## SNMP / LLDP details

### Key OIDs

| Constant | OID | Description |
|---|---|---|
| `OID_IF_DESCR` | `1.3.6.1.2.1.2.2.1.2` | Interface name, indexed by ifIndex — used as port name |
| `OID_IF_ADMIN_STATUS` | `1.3.6.1.2.1.2.2.1.7` | 1=up 2=down (admin configured) |
| `OID_IF_OPER_STATUS` | `1.3.6.1.2.1.2.2.1.8` | 1=up 2=down (actual link state) |
| `OID_IF_SPEED` | `1.3.6.1.2.1.2.2.1.5` | Speed in bps, 32-bit (may saturate at 1G) |
| `OID_IF_HIGH_SPEED` | `1.3.6.1.31.1.1.1.15` | Speed in Mbps, 64-bit (ifXTable, preferred) |
| `OID_IF_ALIAS` | `1.3.6.1.2.1.31.1.1.1.18` | Admin description (ifAlias) |
| `OID_IF_IN_OCTETS` | `1.3.6.1.2.1.2.2.1.10` | Inbound octets counter |
| `OID_IF_OUT_OCTETS` | `1.3.6.1.2.1.2.2.1.16` | Outbound octets counter |
| `OID_LOC_SYS_NAME` | `1.0.8802.1.1.2.1.3.3.0` | Local system hostname (LLDP) |
| `OID_REM_SYS_NAME` | `1.0.8802.1.1.2.1.4.1.1.9` | Neighbor hostname |
| `OID_REM_PORT_DESC` | `1.0.8802.1.1.2.1.4.1.1.8` | Neighbor port description |
| `OID_REM_SYS_CAP` | `1.0.8802.1.1.2.1.4.1.1.12` | Capability bits (bridge/router/wlan) |

### Vendor quirks

- **Aruba OSCX**: `ifDescr` = `1/1/1` format. REST API available for VLAN data (`ARUBA_REST_USER/PASS`).
- **HP ProCurve (old, E5406zl)**: `ifDescr` = `A1`, `A2`. ifAlias contains admin descriptions.
- **HP ProCurve (3810M, 2530)**: `ifDescr` = plain integers `1`, `2`, `3`.
- **lldpLocPortNum ≈ ifIndex** on all standard implementations — used as the join key.
- **Never use lldpLocPortDesc as a comment source** — it equals the admin description on all vendors.

### SNMP walk index formats

- `snmp_walk()` returns `{suffix: value}` where suffix is everything after the base OID.
- Local port table (lldp local): suffix = `portNum` (e.g. `"1"`, `"2"`).
- Remote neighbor table: suffix = `timeMark.portNum.remIdx` (e.g. `"0.1.1"`).
- IF-MIB tables: suffix = `ifIndex` — same as lldpLocPortNum.

## Database schema

| Table | Purpose |
|---|---|
| `events` | Topology change log (switch up/down/appeared) |
| `link_traffic` | Per-port traffic history (in/out bps, errors), retained 10 days |
| `port_counters` | Latest SNMP counter snapshot per port (for delta calculation) |
| `mac_table` | MAC forwarding table, purged after 30 min, `is_edge=1` = access port |
| `node_overrides` | Manual node type overrides, survive topology re-poll |

## Polling architecture

```
lifespan():
  poll_loop()      — runs build_topology() every poll_interval seconds
  mac_poll_loop()  — runs build_mac_tables() every 600 s, starts after 90 s delay
```

`/api/switch_ports` — on-demand per-switch port status, **no DB**, fast SNMP (timeout=snmp_timeout, retries=1), called by frontend every 4 s while Ports tab is open.

## Frontend conventions

- **vis.js DataSet**: always use `.update([...])` in batch, never item-by-item in a loop — causes O(n²) redraws.
- **SSE** (`/api/events`): backend pushes `topology_updated` → frontend calls `loadTopology()`.
- **Node panel tabs**: `['info', 'lldp', 'traffic', 'vlan', 'mac', 'ports']` — index matches `.np-tab` button order.
- **`_applyViewFilter()`** must be called after every `loadTopology()` — otherwise hidden nodes (wifi, other) reappear on refresh.
- **`_currentNodeId`** — currently selected node. `null` when panel is closed.
- **`_portsInterval`** — setInterval handle for live port polling. Always `_stopPortsPolling()` before `closePanel()` and on tab switch away from Ports.
- **Resizable columns**: `_makeResizable(tableEl, savedWidths, onSave)` — must be called after every `innerHTML` replacement that contains a `.lldp-table`. Widths stored in `_portsColWidths` / `_lldpColWidths`.
- **Port filter input** (`#np-ports-filter`) lives in a separate div *above* `#np-ports-content` so it survives polling re-renders. Filter resets when switching to a different node.

## Security rules

- `.env`, `config/switches.txt`, `config/nginx.conf`, `config/htpasswd`, `.claude/` are **gitignored** — never commit them.
- `.env.example`, `config/switches.txt.example`, `config/nginx.conf.example` are the safe templates in git.
- SNMP community string comes from `SNMP_COMMUNITY` env var, never hardcoded.
