import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml

import db

log = logging.getLogger(__name__)

SW_LINKS_FILE = Path(os.getenv("DATA_DIR", "/data")) / "sw_links.json"

# SNMPv2-MIB
OID_SYS_DESCR           = "1.3.6.1.2.1.1.1.0"

# Q-BRIDGE-MIB (HP ProCurve / IEEE 802.1Q)
OID_DOT1Q_VLAN_NAMES    = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # vlanId → name
OID_DOT1Q_VLAN_EGRESS   = "1.3.6.1.2.1.17.7.1.4.2.1.4"  # timeMark.vlanId → portmask
OID_DOT1Q_VLAN_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.2.1.5"  # timeMark.vlanId → portmask
OID_DOT1Q_PVID          = "1.3.6.1.2.1.17.7.1.4.5.1.1"  # portNum → access vlanId

# Standard LLDP-MIB OIDs (IEEE 802.1AB)
OID_LOC_SYS_NAME        = "1.0.8802.1.1.2.1.3.3.0"
OID_LOC_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.7.1.2"
OID_LOC_PORT_ID         = "1.0.8802.1.1.2.1.3.7.1.3"
OID_LOC_PORT_DESC       = "1.0.8802.1.1.2.1.3.7.1.4"
OID_REM_SYS_NAME        = "1.0.8802.1.1.2.1.4.1.1.9"
OID_REM_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.6"
OID_REM_PORT_DESC       = "1.0.8802.1.1.2.1.4.1.1.8"
OID_REM_PORT_ID         = "1.0.8802.1.1.2.1.4.1.1.7"
OID_REM_MAN_ADDR        = "1.0.8802.1.1.2.1.4.2.1.3"
OID_REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
OID_REM_CHASSIS_ID      = "1.0.8802.1.1.2.1.4.1.1.5"
OID_REM_SYS_CAP        = "1.0.8802.1.1.2.1.4.1.1.12"  # lldpRemSysCapEnabled BITS

# IF-MIB OIDs
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_SPEED       = "1.3.6.1.2.1.2.2.1.5"   # bps, 32-bit
OID_IF_HIGH_SPEED  = "1.3.6.1.31.1.1.1.15"   # Mbps, 64-bit (ifXTable, optional)
OID_IF_IN_OCTETS   = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS  = "1.3.6.1.2.1.2.2.1.16"
OID_IF_IN_ERRORS   = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_ERRORS  = "1.3.6.1.2.1.2.2.1.20"

# BRIDGE-MIB / STP OIDs
OID_STP_ROOT_PORT  = "1.3.6.1.2.1.17.2.2.0"   # 0 if this switch is root
OID_STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3" # indexed by dot1dBasePort
OID_STP_PORT_IFIDX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePort → ifIndex

# Q-BRIDGE-MIB MAC forwarding table (dot1qTpFdbTable)
OID_DOT1Q_FDB_PORT   = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # fdbId.a.b.c.d.e.f → bridge port
OID_DOT1Q_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"  # fdbId.a.b.c.d.e.f → status
# Q-BRIDGE-MIB VLAN→fdbId mapping — ProCurve fdbId ≠ vlan_id; invert to get fdb→vlan
OID_DOT1Q_VLAN_FDBID = "1.3.6.1.2.1.17.7.1.4.2.1.3"  # timeMark.vlan_id → fdb_id
# BRIDGE-MIB MAC forwarding table fallback (dot1dTpFdbTable)
OID_DOT1D_FDB_PORT   = "1.3.6.1.2.1.17.4.3.1.2"       # a.b.c.d.e.f → bridge port
OID_DOT1D_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"       # a.b.c.d.e.f → status

_STP_STATES = {"1": "disabled", "2": "blocking", "3": "listening",
               "4": "learning",  "5": "forwarding", "6": "broken"}

_MAX_32BIT = 4_294_967_295


def _fmt_speed(bps_str: str, mbps_str: str = "") -> str:
    try:
        mbps = int(mbps_str)
        if 0 < mbps < _MAX_32BIT:
            return f"{mbps // 1000}G" if mbps >= 1000 else f"{mbps}M"
    except Exception:
        pass
    try:
        bps = int(bps_str)
        if bps == _MAX_32BIT:
            return "10G+"
        mbps = bps // 1_000_000
        if mbps >= 1000:
            return f"{mbps // 1000}G"
        if mbps > 0:
            return f"{mbps}M"
    except Exception:
        pass
    return ""


def _counter_delta_bps(curr: str, prev: str, elapsed_s: float) -> float | None:
    if elapsed_s <= 0:
        return None
    try:
        c, p = int(curr), int(prev)
        delta = c - p if c >= p else (_MAX_32BIT - p + c + 1)
        rate = delta / elapsed_s
        return rate if rate <= 10_000_000_000 else None  # sanity: max 10G
    except Exception:
        return None


def _counter_delta_rate(curr: str, prev: str, elapsed_s: float) -> float | None:
    if elapsed_s <= 0:
        return None
    try:
        c, p = int(curr), int(prev)
        delta = c - p if c >= p else (_MAX_32BIT - p + c + 1)
        return round(delta / elapsed_s, 3)
    except Exception:
        return None


def _decode_portmask(raw: str) -> list[int]:
    """Convert SNMP hex portmask (e.g. 'FF 70 0A C4') to list of 1-based port numbers."""
    ports, port = [], 1
    for byte_str in raw.strip().strip('"').strip().split():
        try:
            b = int(byte_str, 16)
        except ValueError:
            continue
        for i in range(7, -1, -1):
            if b & (1 << i):
                ports.append(port)
            port += 1
    return ports


def load_config() -> dict:
    path = Path(os.getenv("CONFIG_DIR", "/config")) / "config.yml"
    with open(path) as f:
        return yaml.safe_load(f)


def load_switches() -> list[str]:
    def _parse(path: Path) -> list[str]:
        if not path.exists():
            return []
        return [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    config_path = Path(os.getenv("CONFIG_DIR", "/config")) / "switches.txt"
    extra_path  = Path(os.getenv("DATA_DIR", "/data")) / "extra_switches.txt"

    seen, result = set(), []
    for ip in _parse(config_path) + _parse(extra_path):
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def _strip_quotes(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _normalize_chassis_id(raw: str) -> str:
    parts = re.split(r'[:.\s]+', raw.strip())
    if len(parts) == 6:
        try:
            return ':'.join(f'{int(p, 16):02x}' for p in parts)
        except ValueError:
            pass
    return raw.strip().lower()


def _clean_remote_name(name: str) -> str:
    name = name.strip()
    if not name:
        return name
    parts = re.split(r'[:\s.\-]+', name)
    if len(parts) >= 4 and all(re.fullmatch(r'[0-9A-Fa-f]{1,2}', p) for p in parts):
        short = ':'.join(p.lower().zfill(2) for p in parts[:4])
        return short + ('…' if len(parts) > 4 else '')
    return name


_TYPE_PRIORITY: dict[str, int] = {"wifi": 3, "router": 2, "switch": 1, "other": 0}

_RE_MAC_SPACES = re.compile(r'^([0-9A-Fa-f]{2} ){5}[0-9A-Fa-f]{2}$')
_RE_MAC_COLONS = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
_RE_MAC_CPORT  = re.compile(r'^[0-9A-Fa-f]{12}:[Pp]\d+$')


# lldpPortIdSubtype values where lldpPortId contains the real interface name
_PORT_ID_GOOD_SUBTYPES = {"5", "7"}  # interfaceName=5, local=7
# subtype 1 = interfaceAlias (Juniper default) → portId is a comment, skip it
# subtype 3 = macAddress (HP ProCurve)         → handled by _usable_port_id


def _pick_port_name(port_num: str, subtypes: dict, ids: dict, descs: dict) -> str:
    """Choose the best human-readable port name from LLDP data.

    Priority:
      1. lldpPortId when subtype is interfaceName(5) or local(7) and not garbage
      2. lldpPortDesc (actual name on Juniper interfaceAlias, HP ProCurve, etc.)
      3. fallback 'port<num>'
    """
    subtype = subtypes.get(port_num, "").strip()
    port_id = ids.get(port_num, "")
    if subtype in _PORT_ID_GOOD_SUBTYPES:
        name = _usable_port_id(port_id)
        if name:
            return name
    elif not subtype:
        # subtype unknown — try id, fall back to desc
        name = _usable_port_id(port_id)
        if name:
            return name
    return descs.get(port_num) or f"port{port_num}"


def _usable_port_id(s: str) -> str:
    """Return s if it looks like a real interface name, else empty string.

    Filters out HP ProCurve-style garbage: raw MAC addresses (subtype 3)
    and bare ifIndex integers (subtype 7).
    """
    s = s.strip()
    if not s:
        return ""
    if s.isdigit():                    # bare ifIndex
        return ""
    if _RE_MAC_SPACES.match(s):        # "0C 38 3E 3D 19 03"
        return ""
    if _RE_MAC_COLONS.match(s):        # "0c:38:3e:3d:1f:9b"
        return ""
    if _RE_MAC_CPORT.match(s):         # "000413bf8a06:P1"
        return ""
    return s


def _lldp_node_type(raw: str) -> str:
    """Derive node type from lldpRemSysCapEnabled BITS value.

    Priority: wlan > router > bridge > other.
    Handles hex-bytes ("28 00") and text ("bridge router") formats.
    """
    raw = raw.strip().strip('"').strip()
    if not raw:
        return "other"
    parts = raw.split()
    try:
        first_byte = int(parts[0], 16)
        if first_byte & 0x10:  # wlanAccessPoint(3)
            return "wifi"
        if first_byte & 0x08:  # router(4)
            return "router"
        if first_byte & 0x20:  # bridge(2)
            return "switch"
        return "other"
    except (ValueError, IndexError):
        pass
    lower = raw.lower()
    if "wlan" in lower or "access" in lower:
        return "wifi"
    if "router" in lower:
        return "router"
    if "bridge" in lower:
        return "switch"
    return "other"


def _is_infra_cap(raw: str) -> bool:
    """Return True if lldpRemSysCapEnabled bits include bridge(2), wlan(3), or router(4).

    SNMP BITS: bit index counts from MSB of first byte.
    bridge(2)=0x20, wlan(3)=0x10, router(4)=0x08 → infra mask 0x38.
    Handles both hex-bytes ("28 00") and text ("bridge router") formats.
    """
    raw = raw.strip().strip('"').strip()
    if not raw:
        return False
    parts = raw.split()
    try:
        first_byte = int(parts[0], 16)
        return bool(first_byte & 0x38)  # bridge=0x20 | wlan=0x10 | router=0x08
    except (ValueError, IndexError):
        pass
    lower = raw.lower()
    return "bridge" in lower or "router" in lower or "wlan" in lower


async def snmp_get(host: str, community: str, oid: str, timeout: int, retries: int) -> str | None:
    cmd = ["snmpget", "-v2c", "-c", community, f"-t{timeout}", f"-r{retries}", "-Oqv", host, oid]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        value = _strip_quotes(stdout.decode(errors="replace").strip())
        return value or None
    except Exception as e:
        log.debug("snmpget %s %s: %s", host, oid, e)
        return None


async def snmp_walk(host: str, community: str, base_oid: str, timeout: int, retries: int) -> dict:
    cmd = [
        "snmpbulkwalk", "-v2c", "-c", community,
        f"-t{timeout}", f"-r{retries}", "-Oqn",
        host, base_oid,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout * (retries + 1) + 5)
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        log.debug("snmpbulkwalk timeout %s %s", host, base_oid)
        return {}
    except Exception as e:
        log.debug("snmpbulkwalk %s %s: %s", host, base_oid, e)
        return {}

    results = {}
    norm_base = base_oid.lstrip(".")
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) < 2:
            continue
        full_oid = parts[0].lstrip(".")
        value = _strip_quotes(parts[1].strip())
        if full_oid.startswith(norm_base + "."):
            suffix = full_oid[len(norm_base) + 1:]
            results[suffix] = value
    return results


def get_switch_rest_creds(ip: str, cfg: dict) -> tuple[str, str] | None:
    sw_cfg = cfg.get("switches", {}).get(ip, {})
    user = sw_cfg.get("rest_user") or os.getenv("ARUBA_REST_USER", "")
    pwd  = sw_cfg.get("rest_pass") or os.getenv("ARUBA_REST_PASS", "")
    return (user, pwd) if user and pwd else None


async def aruba_rest_vlans(ip: str, user: str, pwd: str, timeout: int) -> dict:
    """Fetch VLAN data via Aruba OSCX REST API.

    Returns {"vlans": [...], "port_pvid": {port_name: vlan_id}} or {} on failure.
    port_pvid keys are Aruba port names (e.g. "1/1/1") — caller converts to ifIndex.
    """
    base = f"https://{ip}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            r = await client.post(
                f"{base}/rest/v1/login",
                data={"username": user, "password": pwd},
            )
            if r.status_code != 200:
                log.warning("Aruba REST login failed %s: HTTP %s", ip, r.status_code)
                return {}

            r_vlans = await client.get(f"{base}/rest/v1/system/vlans?depth=2")
            r_ports = await client.get(f"{base}/rest/v1/system/ports?depth=2")

        vlan_data  = r_vlans.json() if r_vlans.status_code == 200 else {}
        ports_raw  = r_ports.json() if r_ports.status_code == 200 else {}
        # firmware may return list or dict
        if isinstance(ports_raw, list):
            ports_data = {p["name"]: p for p in ports_raw if isinstance(p, dict) and "name" in p}
        else:
            ports_data = ports_raw

        if isinstance(vlan_data, list):
            vlan_data = {str(v["id"]): v for v in vlan_data if isinstance(v, dict) and "id" in v}

        vlan_names: dict[int, str] = {}
        for vid_str, vobj in vlan_data.items():
            try:
                vlan_names[int(vid_str)] = vobj.get("name", vid_str) if isinstance(vobj, dict) else vid_str
            except (ValueError, TypeError):
                pass

        def _resolve_vid(tag) -> int | None:
            if isinstance(tag, dict):
                try:
                    return int(tag.get("id") or tag.get("name", ""))
                except (ValueError, TypeError):
                    return None
            if isinstance(tag, (int, float)):
                return int(tag)
            if isinstance(tag, str):
                try:
                    return int(tag.rstrip("/").split("/")[-1])
                except (ValueError, IndexError):
                    return None
            return None

        port_pvid: dict[str, int] = {}
        vlan_ports: dict[int, set] = {}

        for pname, pobj in ports_data.items():
            if not isinstance(pobj, dict):
                continue
            mode = pobj.get("vlan_mode", "")
            if mode == "access":
                vid = _resolve_vid(pobj.get("vlan_tag"))
                if vid:
                    port_pvid[pname] = vid
                    vlan_ports.setdefault(vid, set()).add(pname)
            elif mode in ("trunk", "native-untagged", "native-tagged"):
                for tag in (pobj.get("vlan_trunks") or []):
                    vid = _resolve_vid(tag)
                    if vid:
                        vlan_ports.setdefault(vid, set()).add(pname)
                native = pobj.get("vlan_tag")
                if native:
                    vid = _resolve_vid(native)
                    if vid:
                        port_pvid[pname] = vid
                        vlan_ports.setdefault(vid, set()).add(pname)

        vlans = [
            {
                "id":       vid,
                "name":     vlan_names.get(vid, str(vid)),
                "egress":   sorted(vlan_ports.get(vid, [])),
                "untagged": sorted(p for p in vlan_ports.get(vid, []) if port_pvid.get(p) == vid),
            }
            for vid in sorted(vlan_names)
        ]

        log.info("Aruba REST %s: %d VLANs, %d access ports", ip, len(vlans), len(port_pvid))
        return {"vlans": vlans, "port_pvid": port_pvid}

    except Exception as e:
        log.warning("Aruba REST failed %s: %s", ip, e)
        return {}


async def poll_switch(ip: str, community: str, timeout: int, retries: int,
                      rest_creds: tuple[str, str] | None = None) -> dict:
    loc_name = await snmp_get(ip, community, OID_LOC_SYS_NAME, timeout, retries)
    if loc_name is None:
        log.warning("Cannot reach %s", ip)
        return {"ip": ip, "name": ip, "links": [], "reachable": False,
                "if_counters": {}, "stp_root": False, "stp_by_ifidx": {}}

    loc_name = loc_name.strip() or ip

    (
        loc_port_subtypes, loc_port_ids, loc_ports,
        rem_names, rem_port_subtypes, rem_port_desc, rem_port_id,
        rem_man_addrs, rem_chassis_sub, rem_chassis_ids, rem_sys_cap_raw,
        if_status, if_speed_bps, if_speed_mbps,
        if_in_oct, if_out_oct, if_in_err, if_out_err,
        stp_port_state_raw, stp_port_ifidx_raw,
        stp_root_port_val, sys_descr_raw,
        vlan_names_raw, vlan_egress_raw, vlan_untagged_raw, port_pvid_raw,
    ) = await asyncio.gather(
        snmp_walk(ip, community, OID_LOC_PORT_ID_SUBTYPE,  timeout, retries),
        snmp_walk(ip, community, OID_LOC_PORT_ID,          timeout, retries),
        snmp_walk(ip, community, OID_LOC_PORT_DESC,        timeout, retries),
        snmp_walk(ip, community, OID_REM_SYS_NAME,         timeout, retries),
        snmp_walk(ip, community, OID_REM_PORT_ID_SUBTYPE,  timeout, retries),
        snmp_walk(ip, community, OID_REM_PORT_DESC,        timeout, retries),
        snmp_walk(ip, community, OID_REM_PORT_ID,          timeout, retries),
        snmp_walk(ip, community, OID_REM_MAN_ADDR,         timeout, retries),
        snmp_walk(ip, community, OID_REM_CHASSIS_SUBTYPE,  timeout, retries),
        snmp_walk(ip, community, OID_REM_CHASSIS_ID,       timeout, retries),
        snmp_walk(ip, community, OID_REM_SYS_CAP,          timeout, retries),
        snmp_walk(ip, community, OID_IF_OPER_STATUS,       timeout, retries),
        snmp_walk(ip, community, OID_IF_SPEED,             timeout, retries),
        snmp_walk(ip, community, OID_IF_HIGH_SPEED,        timeout, retries),
        snmp_walk(ip, community, OID_IF_IN_OCTETS,         timeout, retries),
        snmp_walk(ip, community, OID_IF_OUT_OCTETS,        timeout, retries),
        snmp_walk(ip, community, OID_IF_IN_ERRORS,         timeout, retries),
        snmp_walk(ip, community, OID_IF_OUT_ERRORS,        timeout, retries),
        snmp_walk(ip, community, OID_STP_PORT_STATE,       timeout, retries),
        snmp_walk(ip, community, OID_STP_PORT_IFIDX,       timeout, retries),
        snmp_get(ip,  community, OID_STP_ROOT_PORT,        timeout, retries),
        snmp_get(ip,  community, OID_SYS_DESCR,            timeout, retries),
        snmp_walk(ip, community, OID_DOT1Q_VLAN_NAMES,    timeout, retries),
        snmp_walk(ip, community, OID_DOT1Q_VLAN_EGRESS,   timeout, retries),
        snmp_walk(ip, community, OID_DOT1Q_VLAN_UNTAGGED, timeout, retries),
        snmp_walk(ip, community, OID_DOT1Q_PVID,          timeout, retries),
    )

    sys_descr = re.sub(r'\s*\(/\S.*$', '', (sys_descr_raw or "").split("\n")[0]).strip()

    # Q-BRIDGE-MIB VLAN data (HP ProCurve; empty dict for unsupported switches)
    vlan_names: dict[int, str] = {}
    for sfx, val in vlan_names_raw.items():
        try:
            vlan_names[int(sfx)] = val
        except ValueError:
            pass

    vlan_egress: dict[int, list[int]] = {}
    for sfx, val in vlan_egress_raw.items():
        parts = sfx.split(".")
        try:
            vlan_egress[int(parts[-1])] = _decode_portmask(val)
        except (ValueError, IndexError):
            pass

    vlan_untagged: dict[int, list[int]] = {}
    for sfx, val in vlan_untagged_raw.items():
        parts = sfx.split(".")
        try:
            vlan_untagged[int(parts[-1])] = _decode_portmask(val)
        except (ValueError, IndexError):
            pass

    port_pvid: dict[str, int] = {}
    for sfx, val in port_pvid_raw.items():
        try:
            port_pvid[sfx] = int(val)
        except ValueError:
            pass

    vlans = [
        {
            "id":       vid,
            "name":     vlan_names[vid],
            "egress":   vlan_egress.get(vid, []),
            "untagged": vlan_untagged.get(vid, []),
        }
        for vid in sorted(vlan_names)
    ]

    # STP: build ifidx → state mapping
    stp_root = (stp_root_port_val == "0")
    stp_by_ifidx: dict[str, str] = {}
    for bp, ifidx in stp_port_ifidx_raw.items():
        state = stp_port_state_raw.get(bp, "")
        if state and ifidx:
            stp_by_ifidx[ifidx.strip()] = _STP_STATES.get(state.strip(), "")

    # IF counters keyed by port num (we assume lldpPortNum ≈ ifIndex)
    all_ports = set(if_in_oct) | set(if_out_oct)
    if_counters: dict[str, dict] = {}
    for pn in all_ports:
        try:
            if_counters[pn] = {
                "in_octets":  int(if_in_oct.get(pn, 0)),
                "out_octets": int(if_out_oct.get(pn, 0)),
                "in_errors":  int(if_in_err.get(pn, 0)),
                "out_errors": int(if_out_err.get(pn, 0)),
            }
        except (ValueError, TypeError):
            pass

    # lldpRemManAddrTable index: timeMark.portNum.remIdx.addrSubtype.addrLen.a.b.c.d
    rem_ips: dict[str, str] = {}
    for idx in rem_man_addrs:
        parts = idx.split(".")
        if len(parts) >= 9 and parts[3] == "1" and parts[4] == "4":
            key = ".".join(parts[:3])
            rem_ips[key] = ".".join(parts[5:9])

    links = []
    for idx, rem_name in rem_names.items():
        rem_name = _clean_remote_name(rem_name)
        if not rem_name:
            continue
        parts = idx.split(".")
        if len(parts) < 3:
            continue
        local_port_num = parts[1]
        local_port  = _pick_port_name(local_port_num, loc_port_subtypes, loc_port_ids, loc_ports)
        remote_port = _pick_port_name(idx, rem_port_subtypes, rem_port_id, rem_port_desc).strip()
        remote_ip   = rem_ips.get(".".join(parts[:3]), "")

        chassis_raw = rem_chassis_ids.get(idx, "").strip()
        if rem_chassis_sub.get(idx, "").strip() == "4" and chassis_raw:
            node_key = _normalize_chassis_id(chassis_raw)
        elif remote_ip:
            node_key = f"{rem_name}|{remote_ip}"
        else:
            node_key = f"{rem_name}|{ip}:{local_port}"

        cap_raw = rem_sys_cap_raw.get(idx, "")
        links.append({
            "remote_name":       rem_name,
            "remote_ip":         remote_ip,
            "node_key":          node_key,
            "local_port":        local_port,
            "local_port_num":    local_port_num,
            "remote_port":       remote_port,
            "local_port_status": if_status.get(local_port_num, ""),
            "local_port_speed":  _fmt_speed(
                if_speed_bps.get(local_port_num, ""),
                if_speed_mbps.get(local_port_num, ""),
            ),
            "stp_state":      stp_by_ifidx.get(local_port_num, ""),
            "lldp_is_infra":  _is_infra_cap(cap_raw),
            "lldp_node_type": _lldp_node_type(cap_raw),
        })

    _is_aruba_cx = "aruba" in (sys_descr or "").lower() and bool(
        re.search(r'\b[A-Z]{2}\.10\.', sys_descr or '')
    )
    if rest_creds and _is_aruba_cx:
        rest = await aruba_rest_vlans(ip, rest_creds[0], rest_creds[1], 30)
        if rest:
            # Convert Aruba port names (e.g. "1/1/1") to ifIndex using LLDP loc_ports map
            name_to_ifidx = {desc: pn for pn, desc in loc_ports.items()}

            port_pvid = {
                name_to_ifidx[pname]: vid
                for pname, vid in rest["port_pvid"].items()
                if pname in name_to_ifidx
            }

            def _to_ifidx(port_names_list):
                return sorted(
                    (name_to_ifidx[pn] for pn in port_names_list if pn in name_to_ifidx),
                    key=lambda x: int(x) if x.isdigit() else 0,
                )

            vlans = [
                {
                    "id":       v["id"],
                    "name":     v["name"],
                    "egress":   _to_ifidx(v["egress"]),
                    "untagged": _to_ifidx(v["untagged"]),
                }
                for v in rest["vlans"]
            ]

    return {
        "ip": ip, "name": loc_name, "links": links, "reachable": True,
        "if_counters": if_counters,
        "stp_root":    stp_root,
        "descr":       sys_descr,
        "vlans":       vlans,
        "port_pvid":   port_pvid,
        "port_names":  {pn: _pick_port_name(pn, loc_port_subtypes, loc_port_ids, loc_ports)
                        for pn in loc_ports},
    }


async def build_topology() -> dict:
    cfg        = load_config()
    switches   = load_switches()
    community  = os.getenv("SNMP_COMMUNITY") or cfg.get("community", "SECURECOMMUNITY")
    concurrency = int(cfg.get("concurrency", 20))
    timeout    = int(cfg.get("snmp_timeout", 10))
    retries    = int(cfg.get("snmp_retries", 2))

    sem = asyncio.Semaphore(concurrency)

    async def bounded(ip: str):
        async with sem:
            return await poll_switch(
                ip, community, timeout, retries,
                rest_creds=get_switch_rest_creds(ip, cfg),
            )

    results = await asyncio.gather(*[bounded(ip) for ip in switches], return_exceptions=True)

    nodes: dict[str, dict] = {}
    switch_results = []

    for r in results:
        if isinstance(r, Exception):
            log.error("Unexpected error: %s", r)
            continue
        switch_results.append(r)
        nodes[r["name"]] = {
            "id":         r["name"],
            "label":      r["name"],
            "ip":         r["ip"],
            "reachable":  r["reachable"],
            "managed":    True,
            "node_type":  "switch",
            "stp_root":   r.get("stp_root", False),
            "descr":      r.get("descr", ""),
            "vlans":      r.get("vlans", []),
            "port_pvid":  r.get("port_pvid", {}),
            "port_names": r.get("port_names", {}),
        }

    # Reconcile node_keys: managed switch seen as LLDP neighbor → use its canonical name
    managed_by_name = {r["name"]: r["name"] for r in switch_results}
    for r in switch_results:
        for link in r["links"]:
            if link["remote_name"] in managed_by_name:
                link["node_key"] = managed_by_name[link["remote_name"]]

    # Add LLDP-discovered neighbors not in our polling list
    for r in switch_results:
        for link in r["links"]:
            nk = link["node_key"]
            is_infra  = link.get("lldp_is_infra", False)
            link_type = link.get("lldp_node_type", "other")
            if nk not in nodes:
                nodes[nk] = {
                    "id":            nk,
                    "label":         link["remote_name"],
                    "ip":            link.get("remote_ip", ""),
                    "reachable":     False,
                    "managed":       False,
                    "node_type":     link_type,
                    "stp_root":      False,
                    "lldp_is_infra": is_infra,
                }
            else:
                # device seen from multiple switches: OR infra flag, take highest-priority type
                if is_infra:
                    nodes[nk]["lldp_is_infra"] = True
                existing_type = nodes[nk].get("node_type", "other")
                if _TYPE_PRIORITY.get(link_type, 0) > _TYPE_PRIORITY.get(existing_type, 0):
                    nodes[nk]["node_type"] = link_type

    # ── Traffic & error deltas ────────────────────────────────────────────────
    now_str      = datetime.now(timezone.utc).isoformat(timespec="seconds")
    prev_counters = db.get_counters()
    new_counters: dict = {}
    traffic_lookup: dict[tuple, dict] = {}  # (switch_name, port_num) → deltas

    for r in switch_results:
        for port_num, ctr in r.get("if_counters", {}).items():
            key = (r["ip"], port_num)
            new_counters[key] = {"ts": now_str, **ctr}

            prev = prev_counters.get(key)
            if prev and prev.get("ts"):
                try:
                    elapsed = (
                        datetime.fromisoformat(now_str) -
                        datetime.fromisoformat(prev["ts"])
                    ).total_seconds()
                except Exception:
                    elapsed = 0

                traffic_lookup[(r["name"], port_num)] = {
                    "in_bps":    _counter_delta_bps(ctr["in_octets"],  prev.get("in_octets"),  elapsed),
                    "out_bps":   _counter_delta_bps(ctr["out_octets"], prev.get("out_octets"), elapsed),
                    "in_err_s":  _counter_delta_rate(ctr["in_errors"],  prev.get("in_errors"),  elapsed),
                    "out_err_s": _counter_delta_rate(ctr["out_errors"], prev.get("out_errors"), elapsed),
                }

    db.save_counters(new_counters)

    # Save traffic history for switch-to-switch links only
    managed_set = {r["name"] for r in switch_results}
    sw_traffic: list[dict] = []
    for r in switch_results:
        if not r["reachable"]:
            continue
        for link in r["links"]:
            if link["node_key"] not in managed_set:
                continue
            td = traffic_lookup.get((r["name"], link["local_port_num"]))
            if td and any(v is not None for v in td.values()):
                sw_traffic.append({
                    "switch_ip": r["ip"],
                    "port_num":  link["local_port_num"],
                    "ts":        now_str,
                    **td,
                })
    if sw_traffic:
        db.save_link_traffic(sw_traffic)
    # ─────────────────────────────────────────────────────────────────────────

    # Build reverse port-num lookup: (neighbor, me) → my local_port_num
    # Used to fill remote_port_num for the "to" side of each deduplicated edge.
    _rev_port_num: dict[tuple[str, str], str] = {}
    for r in switch_results:
        for link in r["links"]:
            _rev_port_num[(link["node_key"], r["name"])] = link["local_port_num"]

    # Deduplicate edges
    seen: set = set()
    edges = []
    for r in switch_results:
        for link in r["links"]:
            key = tuple(sorted([
                (r["name"],        link["local_port"]),
                (link["node_key"], link["remote_port"]),
            ]))
            if key not in seen:
                seen.add(key)
                td = traffic_lookup.get((r["name"], link["local_port_num"]), {})
                edges.append({
                    "from":              r["name"],
                    "to":                link["node_key"],
                    "local_port":        link["local_port"],
                    "remote_port":       link["remote_port"],
                    "local_port_status": link.get("local_port_status", ""),
                    "local_port_speed":  link.get("local_port_speed", ""),
                    "stp_state":         link.get("stp_state", ""),
                    "in_bps":            td.get("in_bps"),
                    "out_bps":           td.get("out_bps"),
                    "in_err_s":          td.get("in_err_s"),
                    "out_err_s":         td.get("out_err_s"),
                    "local_port_num":    link["local_port_num"],
                    "remote_port_num":   _rev_port_num.get((r["name"], link["node_key"]), ""),
                    "switch_ip":         r["ip"],
                })

    # ── Persist switch-to-switch links (topology memory) ─────────────────────
    managed_names = {r["name"] for r in switch_results}

    def _is_sw(name: str) -> bool:
        return name in managed_names or nodes.get(name, {}).get("lldp_is_infra", False)

    try:
        cache: dict[tuple, dict] = {
            (e["from"], e["to"]): e
            for e in (json.loads(SW_LINKS_FILE.read_text()) if SW_LINKS_FILE.exists() else [])
        }
    except Exception:
        cache = {}

    for edge in edges:
        if _is_sw(edge["from"]) and _is_sw(edge["to"]):
            cache[(edge["from"], edge["to"])] = {
                "from": edge["from"], "to": edge["to"],
                "local_port": edge["local_port"], "remote_port": edge["remote_port"],
                "last_seen": now_str,
            }

    try:
        SW_LINKS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SW_LINKS_FILE.write_text(json.dumps(list(cache.values()), ensure_ascii=False))
    except Exception as e:
        log.warning("Cannot save sw_links cache: %s", e)

    live_pairs   = {frozenset([e["from"], e["to"]]) for e in edges}
    added_pairs: set = set()
    for (frm, to), cached_edge in cache.items():
        pair = frozenset([frm, to])
        if pair in live_pairs or pair in added_pairs:
            continue
        if frm not in nodes and to not in nodes:
            continue
        for name in (frm, to):
            if name not in nodes:
                nodes[name] = {
                    "id": name, "label": name, "ip": "",
                    "reachable": False, "managed": True, "stp_root": False,
                }
        edges.append({
            "from": frm, "to": to,
            "local_port":  cached_edge.get("local_port", ""),
            "remote_port": cached_edge.get("remote_port", ""),
            "cached":    True,
            "last_seen": cached_edge.get("last_seen", ""),
        })
        added_pairs.add(pair)
    # ─────────────────────────────────────────────────────────────────────────

    reachable_count = sum(1 for r in switch_results if r["reachable"])
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "meta": {
            "polled_at":        now_str,
            "total":            len(switches),
            "reachable_count":  reachable_count,
            "unreachable_count": len(switch_results) - reachable_count,
        },
    }


def _mac_from_suffix(parts: list[str]) -> str | None:
    """Convert list of 6 decimal octets ['0','80','14',...] to 'aa:bb:cc:...'."""
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p):02x}" for p in parts)
    except (ValueError, TypeError):
        return None


async def poll_mac_table(
    ip: str, community: str, timeout: int, retries: int,
    uplink_port_nums: set[str],
    port_pvid: dict[str, int] | None = None,
) -> list[dict]:
    """Return [{mac, switch_ip, port_num, vlan_id, is_edge}] for one switch.

    MAC-table OIDs return dot1dBasePort numbers; LLDP-based uplink_port_nums are
    ifIndex values.  On HP ProCurve these differ, so we always fetch the
    dot1dBasePortIfIndex mapping (OID_STP_PORT_IFIDX) and use it to convert.

    port_pvid ({ifIndex_str: vlan_id}) comes from topology polling and gives the
    authoritative VLAN for each access port.  On ProCurve the fdbId in
    dot1qTpFdbTable is NOT the VLAN ID, so port_pvid is used as the primary
    source; fdbId is only a fallback.
    """
    # Fetch bridge-port→ifIndex map + Q-BRIDGE FDB + vlan→fdbId mapping in parallel
    bp_ifidx_raw, fdb_port_raw, fdb_status_raw, vlan_fdbid_raw = await asyncio.gather(
        snmp_walk(ip, community, OID_STP_PORT_IFIDX,    timeout, retries),
        snmp_walk(ip, community, OID_DOT1Q_FDB_PORT,    timeout, retries),
        snmp_walk(ip, community, OID_DOT1Q_FDB_STATUS,  timeout, retries),
        snmp_walk(ip, community, OID_DOT1Q_VLAN_FDBID,  timeout, retries),
    )

    # dot1dBasePort (str) → ifIndex (str); fall back to identity when absent
    bp_to_ifidx: dict[str, str] = {bp: v.strip() for bp, v in bp_ifidx_raw.items()}

    def _to_ifidx(bridge_port_str: str) -> str:
        bp = bridge_port_str.strip()
        return bp_to_ifidx.get(bp, bp)

    # Invert dot1qVlanFdbId (suffix: timeMark.vlan_id → fdb_id) to get fdbId → vlanId.
    # On HP ProCurve fdbId in dot1qTpFdbTable ≠ vlan_id; this gives the real VLAN.
    fdb_to_vlan: dict[int, int] = {}
    for sfx, val in vlan_fdbid_raw.items():
        try:
            vlan_id  = int(sfx.split(".")[-1])
            fdb_id_v = int(val)
            fdb_to_vlan[fdb_id_v] = vlan_id
        except (ValueError, IndexError):
            pass

    def _vlan_for_port(port_num: str, fdb_id: int | None) -> int | None:
        """Return VLAN: fdb→vlan mapping first (ProCurve fix), then port_pvid, then raw fdbId."""
        if fdb_id is not None:
            v = fdb_to_vlan.get(fdb_id)
            if v is not None:
                return v
        if port_pvid:
            v = port_pvid.get(port_num)
            if v is not None:
                return int(v)
        return fdb_id

    entries: list[dict] = []

    if fdb_port_raw:
        for suffix, port_str in fdb_port_raw.items():
            if fdb_status_raw.get(suffix, "").strip() != "3":  # 3 = learned
                continue
            parts = suffix.split(".")
            if len(parts) != 7:
                continue
            mac = _mac_from_suffix(parts[1:])
            if not mac:
                continue
            port_num = _to_ifidx(port_str)
            if port_num == "0":
                continue
            try:
                fdb_id = int(parts[0])
            except ValueError:
                fdb_id = None
            entries.append({
                "mac":      mac,
                "switch_ip": ip,
                "port_num": port_num,
                "vlan_id":  _vlan_for_port(port_num, fdb_id),
                "is_edge":  0 if port_num in uplink_port_nums else 1,
            })

    if not entries:
        # Fallback: BRIDGE-MIB (no VLAN info, suffix = a.b.c.d.e.f)
        bd_port_raw, bd_status_raw = await asyncio.gather(
            snmp_walk(ip, community, OID_DOT1D_FDB_PORT,   timeout, retries),
            snmp_walk(ip, community, OID_DOT1D_FDB_STATUS, timeout, retries),
        )
        for suffix, port_str in bd_port_raw.items():
            if bd_status_raw.get(suffix, "").strip() != "3":
                continue
            mac = _mac_from_suffix(suffix.split("."))
            if not mac:
                continue
            port_num = _to_ifidx(port_str)
            if port_num == "0":
                continue
            entries.append({
                "mac":      mac,
                "switch_ip": ip,
                "port_num": port_num,
                "vlan_id":  _vlan_for_port(port_num, None),
                "is_edge":  0 if port_num in uplink_port_nums else 1,
            })

    # Heuristic: a port with many unique MACs is an uplink, not an access port.
    # Topology-based detection can miss uplinks when LLDP is asymmetric or a
    # neighbour isn't in the managed set. Threshold of 20 is safe: real access
    # ports rarely exceed a handful of MACs; wrongly-classified uplinks have
    # hundreds or thousands.
    port_mac_count: dict[str, int] = {}
    for e in entries:
        port_mac_count[e["port_num"]] = port_mac_count.get(e["port_num"], 0) + 1
    for e in entries:
        if e["is_edge"] == 1 and port_mac_count[e["port_num"]] > 20:
            e["is_edge"] = 0

    return entries


async def build_mac_tables(topo: dict) -> int:
    """Poll MAC forwarding tables for all reachable switches, save to DB."""
    cfg        = load_config()
    community  = os.getenv("SNMP_COMMUNITY") or cfg.get("community", "SECURECOMMUNITY")
    timeout    = int(cfg.get("snmp_timeout", 10))
    retries    = int(cfg.get("snmp_retries", 2))
    concurrency = int(cfg.get("concurrency", 20))

    managed_ids = {n["id"] for n in topo["nodes"] if n.get("managed")}
    ip_by_name  = {n["id"]: n["ip"] for n in topo["nodes"] if n.get("managed") and n.get("ip")}

    # port_pvid from topology ({ifIndex_str: vlan_id}) — used to fix VLAN on ProCurve
    port_pvid_by_ip: dict[str, dict] = {}
    for n in topo["nodes"]:
        if n.get("managed") and n.get("ip") and n.get("port_pvid"):
            port_pvid_by_ip[n["ip"]] = n["port_pvid"]

    # Build uplink port set per switch IP (ports connected to other managed switches).
    # Each edge has local_port_num (from-side) and remote_port_num (to-side).
    # Both sides must be marked as uplinks so MAC-table edge detection works correctly.
    uplink_ports: dict[str, set[str]] = {}
    for edge in topo["edges"]:
        if edge.get("from") in managed_ids and edge.get("to") in managed_ids:
            sw_ip_from = ip_by_name.get(edge["from"])
            sw_ip_to   = ip_by_name.get(edge["to"])
            if sw_ip_from and edge.get("local_port_num"):
                uplink_ports.setdefault(sw_ip_from, set()).add(edge["local_port_num"])
            if sw_ip_to and edge.get("remote_port_num"):
                uplink_ports.setdefault(sw_ip_to, set()).add(edge["remote_port_num"])

    reachable_ips = [
        n["ip"] for n in topo["nodes"]
        if n.get("managed") and n.get("reachable") and n.get("ip")
    ]

    sem = asyncio.Semaphore(concurrency)
    now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")

    async def bounded_mac(ip: str):
        async with sem:
            rows = await poll_mac_table(
                ip, community, timeout, retries,
                uplink_ports.get(ip, set()),
                port_pvid=port_pvid_by_ip.get(ip, {}),
            )
            for r in rows:
                r["ts"] = now_str
            return rows

    results = await asyncio.gather(*[bounded_mac(ip) for ip in reachable_ips], return_exceptions=True)

    all_entries: list[dict] = []
    for r in results:
        if isinstance(r, Exception):
            log.error("MAC poll error: %s", r)
        else:
            all_entries.extend(r)

    if all_entries:
        db.save_mac_entries(all_entries)
    db.purge_old_macs(minutes=30)

    edge_count = sum(1 for e in all_entries if e["is_edge"] == 1)
    log.info("MAC tables: %d entries (%d edge) from %d switches",
             len(all_entries), edge_count, len(reachable_ips))
    return len(all_entries)


async def refresh_link_counters(switch_ip: str, port_num: str) -> dict:
    """Poll only IF counter OIDs for one switch, compute delta for port_num, update DB."""
    cfg       = load_config()
    community = os.getenv("SNMP_COMMUNITY") or cfg.get("community", "SECURECOMMUNITY")
    timeout   = int(cfg.get("snmp_timeout", 10))
    retries   = int(cfg.get("snmp_retries", 2))

    if_in_oct, if_out_oct, if_in_err, if_out_err = await asyncio.gather(
        snmp_walk(switch_ip, community, OID_IF_IN_OCTETS,  timeout, retries),
        snmp_walk(switch_ip, community, OID_IF_OUT_OCTETS, timeout, retries),
        snmp_walk(switch_ip, community, OID_IF_IN_ERRORS,  timeout, retries),
        snmp_walk(switch_ip, community, OID_IF_OUT_ERRORS, timeout, retries),
    )

    if not if_in_oct and not if_out_oct:
        return {"error": "unreachable"}

    now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")

    new_ctrs: dict = {}
    for pn in set(if_in_oct) | set(if_out_oct):
        try:
            new_ctrs[pn] = {
                "in_octets":  int(if_in_oct.get(pn, 0)),
                "out_octets": int(if_out_oct.get(pn, 0)),
                "in_errors":  int(if_in_err.get(pn, 0)),
                "out_errors": int(if_out_err.get(pn, 0)),
            }
        except (ValueError, TypeError):
            pass

    prev_counters = db.get_counters()
    key  = (switch_ip, port_num)
    prev = prev_counters.get(key)
    ctr  = new_ctrs.get(port_num, {})

    delta: dict = {"in_bps": None, "out_bps": None, "in_err_s": None, "out_err_s": None}
    if prev and prev.get("ts") and ctr:
        elapsed = (
            datetime.fromisoformat(now_str) - datetime.fromisoformat(prev["ts"])
        ).total_seconds()
        delta = {
            "in_bps":    _counter_delta_bps(ctr["in_octets"],  prev.get("in_octets"),  elapsed),
            "out_bps":   _counter_delta_bps(ctr["out_octets"], prev.get("out_octets"), elapsed),
            "in_err_s":  _counter_delta_rate(ctr["in_errors"],  prev.get("in_errors"),  elapsed),
            "out_err_s": _counter_delta_rate(ctr["out_errors"], prev.get("out_errors"), elapsed),
        }

    db.save_counters({(switch_ip, pn): {"ts": now_str, **c} for pn, c in new_ctrs.items()})
    return delta
