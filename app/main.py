import asyncio
import ipaddress
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import db
from poller import build_topology, build_mac_tables, load_config, load_switches, refresh_link_counters, poll_switch_ports, poll_switch_sfp, get_switch_rest_creds, poll_port_live, _hostname_cache, load_node_info_cache
from fastapi import Query

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

DATA_DIR               = Path(os.getenv("DATA_DIR", "/data"))
DATA_FILE              = DATA_DIR / "topology.json"
POSITIONS_FILE         = DATA_DIR / "positions.json"
EXTRA_SWITCHES         = DATA_DIR / "extra_switches.txt"
TRAFFIC_RETENTION_DAYS = int(os.getenv("TRAFFIC_RETENTION_DAYS", "10"))
_polling = False
_poll_interval = 300
_sse_clients: list[asyncio.Queue] = []


async def _broadcast(event: str) -> None:
    dead = []
    for q in _sse_clients:
        try:
            q.put_nowait(f"event: {event}\ndata: {{}}\n\n")
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        try:
            _sse_clients.remove(q)
        except ValueError:
            pass


def _detect_events(prev_nodes: dict, curr_nodes: dict) -> None:
    for node_id, node in curr_nodes.items():
        prev = prev_nodes.get(node_id)
        label = node.get("label") or node_id
        if prev is None:
            if node.get("managed"):
                db.log_event("switch_appeared", node_id, label, {"ip": node.get("ip", "")})
            else:
                db.log_event("device_appeared", node_id, label, {"ip": node.get("ip", "")})
        elif node.get("managed"):
            if prev.get("reachable") and not node.get("reachable"):
                db.log_event("switch_down", node_id, label)
            elif not prev.get("reachable") and node.get("reachable"):
                db.log_event("switch_up", node_id, label)

    for node_id, prev in prev_nodes.items():
        if node_id not in curr_nodes:
            label = prev.get("label") or node_id
            event = "switch_removed" if prev.get("managed") else "device_removed"
            db.log_event(event, node_id, label)


async def run_poll():
    global _polling
    _polling = True
    await _broadcast("polling_started")
    try:
        log.info("Polling switches...")
        t0 = time.monotonic()

        # Load previous state for change detection
        prev_nodes: dict = {}
        if DATA_FILE.exists():
            try:
                prev_data = json.loads(DATA_FILE.read_text())
                prev_nodes = {n["id"]: n for n in prev_data.get("nodes", [])}
            except Exception:
                pass

        topo = await build_topology()
        topo["meta"]["duration_s"]    = round(time.monotonic() - t0, 1)
        topo["meta"]["poll_interval"] = _poll_interval

        # Apply manual node type overrides (stored in DB, survive re-polling)
        overrides = db.get_node_type_overrides()
        if overrides:
            for node in topo["nodes"]:
                if node["id"] in overrides:
                    node["node_type"] = overrides[node["id"]]
                    node["node_type_manual"] = True

        # Enrich nodes with MAC counts from current mac_table
        mac_counts = db.get_mac_counts()
        if mac_counts:
            for node in topo["nodes"]:
                counts = mac_counts.get(node.get("ip", ""))
                if counts:
                    node["mac_total"] = counts["total"]
                    node["mac_edge"]  = counts["edge"]
            topo["meta"]["mac_total"] = sum(v["total"] for v in mac_counts.values())
            topo["meta"]["mac_edge"]  = sum(v["edge"]  for v in mac_counts.values())

        # Detect topology changes and log to DB
        curr_nodes = {n["id"]: n for n in topo["nodes"]}
        _detect_events(prev_nodes, curr_nodes)

        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        DATA_FILE.write_text(json.dumps(topo, ensure_ascii=False))
        db.purge_old_traffic(TRAFFIC_RETENTION_DAYS)

        m = topo["meta"]
        log.info(
            "Topology saved: %d nodes, %d edges, %d/%d reachable, %.1fs",
            len(topo["nodes"]), len(topo["edges"]),
            m["reachable_count"], m["total"], m["duration_s"],
        )
        await _broadcast("topology_updated")
    except Exception as e:
        log.error("Poll failed: %s", e)
    finally:
        _polling = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _poll_interval
    db.init()
    _hostname_cache.update(db.get_known_hostnames())
    load_node_info_cache()
    cfg      = load_config()
    interval = int(cfg.get("poll_interval", 300))
    _poll_interval = interval

    async def poll_loop():
        while True:
            await run_poll()
            await asyncio.sleep(interval)

    async def mac_poll_loop():
        await asyncio.sleep(90)  # wait for first topology poll to complete
        while True:
            if DATA_FILE.exists():
                try:
                    topo = json.loads(DATA_FILE.read_text())
                    await build_mac_tables(topo)
                except Exception as e:
                    log.error("MAC poll failed: %s", e)
            await asyncio.sleep(600)

    task     = asyncio.create_task(poll_loop())
    mac_task = asyncio.create_task(mac_poll_loop())
    yield
    task.cancel()
    mac_task.cancel()


app = FastAPI(title="Network Topology", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/events")
async def sse_events(request: Request):
    q: asyncio.Queue = asyncio.Queue(maxsize=10)
    _sse_clients.append(q)

    async def generate():
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=25)
                    yield msg
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            try:
                _sse_clients.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/topology")
async def get_topology():
    if DATA_FILE.exists():
        return JSONResponse(json.loads(DATA_FILE.read_text()))
    return JSONResponse({"nodes": [], "edges": []})


@app.get("/api/history")
async def get_history(limit: int = 100):
    return JSONResponse(db.get_events(limit))


@app.post("/api/refresh")
async def trigger_refresh():
    if _polling:
        return {"status": "already_running"}
    asyncio.create_task(run_poll())
    return {"status": "started"}


@app.post("/api/add_switch")
async def add_switch(ip: str = Body(..., embed=True)):
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse({"status": "invalid_ip"}, status_code=400)

    if ip in load_switches():
        return {"status": "already_exists"}

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(EXTRA_SWITCHES, "a") as f:
        f.write(ip + "\n")
    log.info("Added switch %s to monitoring", ip)

    if not _polling:
        asyncio.create_task(run_poll())
    return {"status": "added"}


@app.get("/api/link_traffic")
async def get_link_traffic(
    switch_ip: str = Query(...),
    port_num:  str = Query(...),
    hours:     int = Query(24, ge=1, le=720),
):
    return JSONResponse(db.get_link_traffic(switch_ip, port_num, hours))


@app.get("/api/stats/top_ports")
async def stats_top_ports(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(10, ge=1, le=50),
):
    rows = db.get_top_ports(hours, limit)
    name_by_ip: dict[str, str] = {}
    port_by_key: dict[tuple, str] = {}
    if DATA_FILE.exists():
        try:
            topo = json.loads(DATA_FILE.read_text())
            for n in topo.get("nodes", []):
                if n.get("ip"):
                    name_by_ip[n["ip"]] = n.get("label") or n["id"]
            for e in topo.get("edges", []):
                if e.get("switch_ip") and e.get("local_port_num"):
                    port_by_key[(e["switch_ip"], e["local_port_num"])] = e.get("local_port", "")
        except Exception:
            pass
    for r in rows:
        r["switch_name"] = name_by_ip.get(r["switch_ip"], r["switch_ip"])
        r["port_name"]   = port_by_key.get((r["switch_ip"], r["port_num"]), f"port{r['port_num']}")
    return JSONResponse(rows)


@app.get("/api/stats/switch_traffic")
async def stats_switch_traffic(hours: int = Query(24, ge=1, le=720)):
    rows = db.get_switch_traffic(hours)
    name_by_ip: dict[str, str] = {}
    if DATA_FILE.exists():
        try:
            topo = json.loads(DATA_FILE.read_text())
            for n in topo.get("nodes", []):
                if n.get("ip"):
                    name_by_ip[n["ip"]] = n.get("label") or n["id"]
        except Exception:
            pass
    for r in rows:
        r["switch_name"] = name_by_ip.get(r["switch_ip"], r["switch_ip"])
    return JSONResponse(rows)


@app.post("/api/refresh_link")
async def api_refresh_link(switch_ip: str = Body(...), port_num: str = Body(...)):
    result = await refresh_link_counters(switch_ip, port_num)
    if "error" in result:
        return JSONResponse(result, status_code=503)
    return result


@app.delete("/api/switch")
async def remove_switch(ip: str = Body(..., embed=True)):
    ip = ip.strip()
    if not EXTRA_SWITCHES.exists():
        return {"status": "not_found"}

    lines = EXTRA_SWITCHES.read_text().splitlines()
    new_lines = [l for l in lines if l.strip() != ip]
    if len(new_lines) == len(lines):
        return {"status": "not_found"}

    EXTRA_SWITCHES.write_text("\n".join(new_lines) + ("\n" if new_lines else ""))
    log.info("Removed switch %s from monitoring", ip)
    return {"status": "removed"}


_VALID_NODE_TYPES = {"switch", "router", "wifi", "other"}


@app.patch("/api/nodes/{node_id}")
async def patch_node(node_id: str, node_type: str = Body(..., embed=True)):
    if node_type not in _VALID_NODE_TYPES:
        return JSONResponse({"error": "invalid type"}, status_code=400)
    db.set_node_type_override(node_id, node_type)
    if DATA_FILE.exists():
        try:
            topo = json.loads(DATA_FILE.read_text())
            for node in topo["nodes"]:
                if node["id"] == node_id:
                    node["node_type"] = node_type
                    node["node_type_manual"] = True
                    break
            DATA_FILE.write_text(json.dumps(topo, ensure_ascii=False))
        except Exception:
            pass
    return {"status": "ok"}


@app.get("/api/positions")
async def get_positions():
    if POSITIONS_FILE.exists():
        return JSONResponse(json.loads(POSITIONS_FILE.read_text()))
    return JSONResponse({})


@app.post("/api/positions")
async def save_positions_api(positions: dict = Body(...)):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    POSITIONS_FILE.write_text(json.dumps(positions))
    return {"status": "ok"}


def _compute_path(mac: str, topo: dict) -> dict | None:
    from collections import deque

    all_entries = db.get_mac_entries(mac)
    if not all_entries:
        return None

    ip_to_node: dict[str, str] = {}
    ip_to_name: dict[str, str] = {}
    port_names_by_ip: dict[str, dict] = {}
    for n in topo["nodes"]:
        if n.get("ip"):
            ip_to_node[n["ip"]] = n["id"]
            ip_to_name[n["ip"]] = n.get("label") or n["id"]
        if n.get("ip") and n.get("port_names"):
            port_names_by_ip[n["ip"]] = n["port_names"]

    for e in all_entries:
        e["switch_name"] = ip_to_name.get(e["switch_ip"], e["switch_ip"])
        pnames = port_names_by_ip.get(e["switch_ip"], {})
        e["port_name"] = pnames.get(str(e["port_num"]), f"port{e['port_num']}")

    edge_entries = [e for e in all_entries if e.get("is_edge") == 1]
    if not edge_entries:
        return {"mac": mac, "found": False, "entries": all_entries}

    # Prefer entries from the most recent poll cycle.
    # Stale is_edge=1 entries from unreachable switches (older timestamp) are
    # discarded so they don't override fresh data from the current poll.
    edge_entries.sort(key=lambda e: e["ts"], reverse=True)
    latest_ts = edge_entries[0]["ts"]
    fresh = [e for e in edge_entries if e["ts"] == latest_ts]
    if fresh:
        edge_entries = fresh

    entry = edge_entries[0]
    edge_sw_ip   = entry["switch_ip"]
    edge_sw_node = ip_to_node.get(edge_sw_ip)

    if not edge_sw_node:
        return {
            "mac": mac, "found": True, "entry": entry,
            "edge_switch": entry["switch_name"], "edge_switch_ip": edge_sw_ip,
            "edge_port": entry["port_name"], "edge_port_num": entry["port_num"],
            "vlan_id": entry.get("vlan_id"),
            "path_nodes": [], "path_edges": [], "all_entries": all_entries,
        }

    managed_ids = {n["id"] for n in topo["nodes"] if n.get("managed")}
    adjacency: dict[str, list] = {}
    for edge in topo["edges"]:
        frm, to = edge["from"], edge["to"]
        if frm in managed_ids and to in managed_ids:
            adjacency.setdefault(frm, []).append({"to": to, "edge": edge})
            adjacency.setdefault(to, []).append({"to": frm, "edge": edge})

    root_nodes = [n["id"] for n in topo["nodes"] if n.get("stp_root") and n.get("managed")]
    if not root_nodes:
        degree: dict[str, int] = {}
        for edge in topo["edges"]:
            if edge["from"] in managed_ids: degree[edge["from"]] = degree.get(edge["from"], 0) + 1
            if edge["to"]   in managed_ids: degree[edge["to"]]   = degree.get(edge["to"],   0) + 1
        root_nodes = [max(degree, key=degree.get)] if degree else []

    root_set = set(root_nodes)

    if edge_sw_node in root_set:
        path_nodes: list[str] = [edge_sw_node]
        path_edges: list[dict] = []
    else:
        queue: deque = deque([(edge_sw_node, [edge_sw_node], [])])
        visited = {edge_sw_node}
        path_nodes = [edge_sw_node]
        path_edges = []
        while queue:
            current, pnodes, pedges = queue.popleft()
            if current in root_set:
                path_nodes = pnodes
                path_edges = pedges
                break
            for nb in adjacency.get(current, []):
                if nb["to"] not in visited:
                    visited.add(nb["to"])
                    queue.append((nb["to"], pnodes + [nb["to"]], pedges + [nb["edge"]]))

    return {
        "mac": mac, "found": True, "entry": entry,
        "edge_switch": edge_sw_node, "edge_switch_ip": edge_sw_ip,
        "edge_port": entry["port_name"], "edge_port_num": entry["port_num"],
        "vlan_id": entry.get("vlan_id"),
        "path_nodes": path_nodes,
        "path_edges": [{"from": e["from"], "to": e["to"]} for e in path_edges],
        "all_entries": all_entries,
    }


@app.get("/api/switch_macs")
async def switch_macs_api(switch_ip: str = Query(...)):
    rows = db.get_switch_macs(switch_ip)
    port_names: dict[str, str] = {}
    if DATA_FILE.exists():
        try:
            topo = json.loads(DATA_FILE.read_text())
            for n in topo.get("nodes", []):
                if n.get("ip") == switch_ip and n.get("port_names"):
                    port_names = n["port_names"]
                    break
        except Exception:
            pass
    for r in rows:
        r["port_name"] = port_names.get(str(r["port_num"]), str(r["port_num"]))
    return JSONResponse(rows)


@app.get("/api/mac_search")
async def mac_search_api(q: str = Query(""), limit: int = Query(20, ge=1, le=100)):
    if len(q) < 2:
        return JSONResponse([])
    results = db.search_macs(q, limit)
    name_by_ip: dict[str, str] = {}
    if DATA_FILE.exists():
        try:
            topo = json.loads(DATA_FILE.read_text())
            name_by_ip = {n["ip"]: n.get("label") or n["id"] for n in topo["nodes"] if n.get("ip")}
        except Exception:
            pass
    for r in results:
        r["switch_name"] = name_by_ip.get(r["switch_ip"], r["switch_ip"])
    return JSONResponse(results)


@app.get("/api/switch_ports")
async def switch_ports_api(switch_ip: str = Query(...)):
    cfg       = load_config()
    community = os.getenv("SNMP_COMMUNITY") or cfg.get("community", "SECURECOMMUNITY")
    timeout   = int(cfg.get("snmp_timeout", 10))
    ports     = await poll_switch_ports(switch_ip, community, timeout, retries=1)
    return JSONResponse(ports)


@app.get("/api/port_live")
async def port_live_api(switch_ip: str = Query(...), ifindex: str = Query(...)):
    cfg       = load_config()
    community = os.getenv("SNMP_COMMUNITY") or cfg.get("community", "SECURECOMMUNITY")
    timeout   = int(cfg.get("snmp_timeout", 10))
    data      = await poll_port_live(switch_ip, community, timeout, ifindex)
    return JSONResponse(data)


@app.get("/api/switch_sfp")
async def switch_sfp_api(switch_ip: str = Query(...)):
    cfg       = load_config()
    community = os.getenv("SNMP_COMMUNITY") or cfg.get("community", "SECURECOMMUNITY")
    timeout   = int(cfg.get("snmp_timeout", 10))
    creds     = get_switch_rest_creds(switch_ip, cfg)
    user, pwd = creds if creds else ("", "")
    data      = await poll_switch_sfp(switch_ip, community, timeout, user, pwd)
    return JSONResponse(data)


@app.get("/api/mac_route")
async def mac_route_api(mac: str = Query(...)):
    mac = mac.lower().replace("-", ":").strip()
    if not DATA_FILE.exists():
        return JSONResponse({"error": "no topology"}, status_code=503)
    try:
        topo = json.loads(DATA_FILE.read_text())
    except Exception:
        return JSONResponse({"error": "topology read error"}, status_code=503)
    result = _compute_path(mac, topo)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(result)
