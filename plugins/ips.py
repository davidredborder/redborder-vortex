import hashlib
import json
import os
import socket
import struct
import time
import urllib.parse
import zlib

_CACHE = {}
_CACHE_TTL = 60.0
_MAX_CACHE_SIZE = 10000
_LAST_AEROSPIKE_FAILURE = {}
_CIRCUIT_BREAKER_SECS = 30.0
_CONFIG = {}

AEROSPIKE_CONF = os.environ.get("AEROSPIKE_CONF", "/var/www/rb-rails/config/aerospike.yml")


def register(config):
    global _CONFIG
    if isinstance(config, dict):
        _CONFIG.update(config)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Unexpected EOF from Aerospike socket")
        buf.extend(chunk)
    return bytes(buf)


def _as_key_digest(set_name, key_val):
    h = hashlib.new("ripemd160")
    h.update(set_name.encode("utf-8"))
    h.update(b"\x03")  # ParticleType::STRING = 3
    h.update(str(key_val).encode("utf-8"))
    return h.digest()


def _as_field(field_type, data_bytes):
    return struct.pack(">IB", len(data_bytes) + 1, field_type) + data_bytes


def _unpack_msgpack_val(data, pos):
    if pos >= len(data):
        return None, pos
    b = data[pos]
    pos += 1
    if b <= 0x7F:
        return b, pos
    if b >= 0xE0:
        return b - 256, pos
    if 0x80 <= b <= 0x8F:
        count = b & 0x0F
        out = {}
        for _ in range(count):
            k, pos = _unpack_msgpack_val(data, pos)
            v, pos = _unpack_msgpack_val(data, pos)
            out[k] = v
        return out, pos
    if 0x90 <= b <= 0x9F:
        count = b & 0x0F
        return _unpack_msgpack_array_items(data, pos, count)
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        raw = data[pos:pos + n]
        return _decode_as_particle_in_msgpack(raw), pos + n
    if b == 0xC0:
        return None, pos
    if b == 0xC2:
        return False, pos
    if b == 0xC3:
        return True, pos
    if b in (0xC4, 0xD9):
        n = data[pos]
        pos += 1
        raw = data[pos:pos + n]
        return _decode_as_particle_in_msgpack(raw), pos + n
    if b in (0xC5, 0xDA):
        n = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        raw = data[pos:pos + n]
        return _decode_as_particle_in_msgpack(raw), pos + n
    if b in (0xC6, 0xDB):
        n = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        raw = data[pos:pos + n]
        return _decode_as_particle_in_msgpack(raw), pos + n
    if b == 0xCC:
        return data[pos], pos + 1
    if b == 0xCD:
        return struct.unpack(">H", data[pos:pos + 2])[0], pos + 2
    if b == 0xCE:
        return struct.unpack(">I", data[pos:pos + 4])[0], pos + 4
    if b == 0xCF:
        return struct.unpack(">Q", data[pos:pos + 8])[0], pos + 8
    if b == 0xD0:
        return struct.unpack(">b", data[pos:pos + 1])[0], pos + 1
    if b == 0xD1:
        return struct.unpack(">h", data[pos:pos + 2])[0], pos + 2
    if b == 0xD2:
        return struct.unpack(">i", data[pos:pos + 4])[0], pos + 4
    if b == 0xD3:
        return struct.unpack(">q", data[pos:pos + 8])[0], pos + 8
    if b == 0xDC:
        count = struct.unpack(">H", data[pos:pos + 2])[0]
        return _unpack_msgpack_array_items(data, pos + 2, count)
    if b == 0xDD:
        count = struct.unpack(">I", data[pos:pos + 4])[0]
        return _unpack_msgpack_array_items(data, pos + 4, count)
    # MsgPack fixext / ext types used for CDT flags
    if 0xD4 <= b <= 0xD8:
        ext_len = 1 << (b - 0xD4)
        return ("__ext__",), pos + 1 + ext_len
    if b == 0xC7:
        ext_len = data[pos]
        return ("__ext__",), pos + 2 + ext_len
    return None, len(data)


def _decode_as_particle_in_msgpack(raw):
    if not raw:
        return ""
    ptype = raw[0]
    if ptype == 3:
        return raw[1:].decode("utf-8", errors="replace")
    if ptype == 4:
        return raw[1:]
    return raw.decode("utf-8", errors="replace")


def _unpack_msgpack_array_items(data, pos, count):
    arr = []
    for i in range(count):
        val, pos = _unpack_msgpack_val(data, pos)
        if i == 0 and val == ("__ext__",):
            continue
        arr.append(val)
    return arr, pos


def _decode_particle(p_type, val_raw):
    if p_type == 1:  # INTEGER
        return struct.unpack(">q", val_raw)[0] if len(val_raw) == 8 else 0
    if p_type == 2:  # DOUBLE
        return struct.unpack(">d", val_raw)[0] if len(val_raw) == 8 else 0.0
    if p_type == 3:  # STRING
        return val_raw.decode("utf-8", errors="replace")
    if p_type == 17:  # BOOL
        return bool(val_raw[0]) if val_raw else False
    if p_type == 20:  # LIST
        val, _ = _unpack_msgpack_val(val_raw, 0)
        return val if isinstance(val, list) else []
    return None


def _as_get_record(sock, namespace, set_name, key_val, timeout_ms=1000):
    digest = _as_key_digest(set_name, key_val)
    fields = (
        _as_field(0, namespace.encode("utf-8"))
        + _as_field(1, set_name.encode("utf-8"))
        + _as_field(4, digest)
    )
    msg_len = 22 + len(fields)
    proto = (2 << 56) | (3 << 48) | msg_len
    # info1 = 0x03 (INFO1_READ | INFO1_GET_ALL)
    hdr = struct.pack(">QBBBBBBIIIHH", proto, 22, 0x03, 0, 0, 0, 0, 0, 0, timeout_ms, 3, 0)
    sock.sendall(hdr + fields)

    resp_proto_raw = _recv_exact(sock, 8)
    resp_proto = struct.unpack(">Q", resp_proto_raw)[0]
    msg_type = (resp_proto >> 48) & 0xFF
    resp_size = resp_proto & 0xFFFFFFFFFFFF
    payload = _recv_exact(sock, resp_size)
    if msg_type == 4:
        payload = zlib.decompress(payload[8:])

    hdr_rem = payload[:22]
    body = payload[22:]
    result_code = hdr_rem[5]
    if result_code == 2:  # KEY_NOT_FOUND_ERROR
        return {}
    if result_code != 0:
        raise RuntimeError(f"Aerospike GET error code {result_code}")

    field_count, op_count = struct.unpack(">HH", hdr_rem[18:22])
    pos = 0
    for _ in range(field_count):
        f_sz = struct.unpack(">I", body[pos:pos + 4])[0]
        pos += 4 + f_sz

    bins = {}
    for _ in range(op_count):
        op_sz = struct.unpack(">I", body[pos:pos + 4])[0]
        p_type = body[pos + 5]
        name_len = body[pos + 7]
        b_name = body[pos + 8:pos + 8 + name_len].decode("utf-8", errors="replace")
        val_raw = body[pos + 8 + name_len:pos + 4 + op_sz]
        pos += 4 + op_sz
        bins[b_name] = _decode_particle(p_type, val_raw)
    return bins


def _get_aerospike_host(config_override=None):
    if config_override and isinstance(config_override, str):
        return config_override
    if os.path.exists(AEROSPIKE_CONF):
        try:
            import yaml
            with open(AEROSPIKE_CONF, "r") as f:
                conf = yaml.safe_load(f)
            servers = conf.get("production", {}).get("servers", [])
            if servers and isinstance(servers, list) and isinstance(servers[0], str):
                return servers[0]
        except Exception:
            pass
    return "127.0.0.1:3000"


def _prune_cache_if_needed():
    global _CACHE
    if len(_CACHE) > _MAX_CACHE_SIZE:
        now = time.time()
        # Remove expired entries
        _CACHE = {k: v for k, v in _CACHE.items() if (now - v[1]) < _CACHE_TTL}
        # If still oversized, clear half
        if len(_CACHE) > _MAX_CACHE_SIZE:
            keys = list(_CACHE.keys())
            for k in keys[:len(keys) // 2]:
                _CACHE.pop(k, None)


def _batch_query_aerospike(queries, namespace="malware", server_override=None):
    """
    Batches multiple Aerospike lookups (hash, URL, IPs) over a direct TCP socket
    speaking the Aerospike binary protocol (AS_MSG).
    `queries` is a list of tuples: [ (set_name, key_val), ... ]
    Returns a dict mapping (set_name, str(key_val)) -> dict of bins.
    """
    global _LAST_AEROSPIKE_FAILURE

    results = {}
    needed = []
    now = time.time()

    for set_name, key_val in queries:
        if not key_val:
            continue
        ck = f"{set_name}:{key_val}"
        if ck in _CACHE:
            val, ts = _CACHE[ck]
            if (now - ts) < _CACHE_TTL:
                results[(set_name, str(key_val))] = val
                continue
        needed.append({"set": set_name, "key": str(key_val)})

    if not needed:
        return results

    host_port = _get_aerospike_host(server_override)
    last_fail = _LAST_AEROSPIKE_FAILURE.get(host_port, 0)
    if last_fail > 0 and (now - last_fail) < _CIRCUIT_BREAKER_SECS:
        for q in needed:
            results[(q["set"], q["key"])] = {}
        return results

    if isinstance(host_port, str) and ":" in host_port:
        host, port_str = host_port.split(":", 1)
    else:
        host, port_str = str(host_port or "127.0.0.1"), "3000"

    try:
        port = int(port_str)
    except ValueError:
        port = 3000

    ns = namespace or "malware"
    try:
        with socket.create_connection((host, port), timeout=1.5) as sock:
            sock.settimeout(1.5)
            for q in needed:
                s = q["set"]
                k = q["key"]
                ck = f"{host_port}:{s}:{k}"
                try:
                    bins = _as_get_record(sock, ns, s, k)
                except Exception:
                    bins = {}
                _CACHE[f"{s}:{k}"] = (bins, now)
                results[(s, k)] = bins
        _LAST_AEROSPIKE_FAILURE.pop(host_port, None)
        _prune_cache_if_needed()
        return results
    except Exception:
        _LAST_AEROSPIKE_FAILURE[host_port] = time.time()

    for q in needed:
        results[(q["set"], q["key"])] = {}
    return results


def size_to_range(size):
    try:
        size = int(size)
    except (ValueError, TypeError):
        return None
    if size < 0:
        return None
    if size < 1024:
        return "<1kB"
    elif size < (1024 * 1024):
        return "1kB-1MB"
    elif size < (10 * 1024 * 1024):
        return "1MB-10MB"
    elif size < (50 * 1024 * 1024):
        return "10MB-50MB"
    elif size < (100 * 1024 * 1024):
        return "50MB-100MB"
    elif size < (500 * 1024 * 1024):
        return "100MB-500MB"
    elif size < (1024 * 1024 * 1024):
        return "500MB-1GB"
    else:
        return ">1GB"


def ips_filter(event, config=None):
    """
    Implements legacy logstash-filter-ips-2.0.0:
    - Checks for sha256. If missing, cancels the event.
    - Sets type='ips', hash=sha256.
    - Normalizes URL, file_name, file_size range, application_id_name.
    - Enriches hash_score, url_score, ip_score from Aerospike records.
    """
    sha256 = event.get("sha256")
    if not sha256:
        event.cancel()
        return event

    event.set("hash", sha256)
    event.set("type", "ips")

    file_hostname = event.get("file_hostname") or ""
    file_uri = event.get("file_uri") or ""
    url = None

    if file_hostname and file_uri:
        url = f"http://{file_hostname}{file_uri}"
        event.set("url", url)

    try:
        comb = (file_hostname or "") + (file_uri or "")
        if comb:
            file_name = os.path.basename(comb)
            if file_name:
                event.set("file_name", file_name)
    except Exception:
        if file_uri:
            event.set("file_name", file_uri)

    file_size = event.get("file_size")
    if file_size is not None:
        size_range = size_to_range(file_size)
        if size_range:
            event.set("file_size", size_range)

    if event.get("file_hostname"):
        event.set("application_id_name", "http")
    elif event.get("email_sender"):
        event.set("application_id_name", "smtp")
    elif event.get("ftp_user"):
        event.set("application_id_name", "ftp")
        event.set("client_id", event.get("ftp_user"))
    elif event.get("smb_uid"):
        event.set("application_id_name", "smb")
        event.set("client_id", event.get("smb_uid"))

    # Config options
    cfg = config if isinstance(config, dict) else _CONFIG
    ns = cfg.get("aerospike_namespace", "malware")
    server_override = cfg.get("aerospike_server")

    # Batch queries for hash, url, src IP, dst IP
    src = event.get("src")
    dst = event.get("dst")

    batch_queries = [("hashScores", sha256)]
    if url:
        batch_queries.append(("urlScores", url))
    if src:
        batch_queries.append(("ipScores", src))
    if dst:
        batch_queries.append(("ipScores", dst))

    batch_res = _batch_query_aerospike(batch_queries, namespace=ns, server_override=server_override)

    # 1. Enrich Hash Scores
    data_hash = batch_res.get(("hashScores", str(sha256)), {})
    if data_hash:
        list_type = data_hash.get("list_type")
        raw_score = data_hash.get("score")
        if list_type == "black":
            score = 100
            h_list = "black"
        elif list_type == "white":
            score = 0
            h_list = "white"
        else:
            score = raw_score if raw_score is not None else -1
            h_list = list_type if list_type else "none"
        event.set("hash_score", score)
        event.set("hash_list_type", h_list)
    else:
        event.set("hash_score", -1)
        event.set("hash_list_type", "none")

    # 2. Enrich URL Scores
    if url:
        data_url = batch_res.get(("urlScores", str(url)), {})
        if data_url:
            list_type = data_url.get("list_type")
            raw_score = data_url.get("score")
            if list_type == "black":
                score = 100
                u_list = "black"
            elif list_type == "white":
                score = 0
                u_list = "white"
            else:
                score = raw_score if raw_score is not None else -1
                u_list = list_type if list_type else "none"
            event.set("url_score", score)
            event.set("url_list_type", u_list)
        else:
            event.set("url_score", -1)
            event.set("url_list_type", "none")

    # 3. Enrich IP Scores
    data_src = batch_res.get(("ipScores", str(src)), {}) if src else {}
    data_dst = batch_res.get(("ipScores", str(dst)), {}) if dst else {}

    score_src = data_src.get("score") if data_src else None
    score_dst = data_dst.get("score") if data_dst else None
    list_src = data_src.get("list_type")
    list_dst = data_dst.get("list_type")

    if list_src == "black":
        score_src = 100
    elif list_src == "white":
        score_src = 0

    if list_dst == "black":
        score_dst = 100
    elif list_dst == "white":
        score_dst = 0

    s_src = score_src if (score_src is not None and score_src >= 0) else -1
    s_dst = score_dst if (score_dst is not None and score_dst >= 0) else -1

    if s_src > 0 and s_dst > 0:
        event.set("ip_direction", "both")
        event.set("ip_score", max(s_src, s_dst))
        event.set("ip_list_type", list_src if s_src >= s_dst else list_dst)
    elif s_src > 0:
        event.set("ip_direction", "source")
        event.set("ip_score", s_src)
        event.set("ip_list_type", list_src or "none")
    elif s_dst > 0:
        event.set("ip_direction", "destination")
        event.set("ip_score", s_dst)
        event.set("ip_list_type", list_dst or "none")
    elif s_src == 0 or s_dst == 0:
        event.set("ip_direction", "none")
        event.set("ip_score", 0)
        event.set("ip_list_type", "white")
    else:
        event.set("ip_direction", "none")
        event.set("ip_score", -1)
        event.set("ip_list_type", "none")

    return event


def unescape_fields(event, config=None):
    """
    Percent-unescapes 'file_uri', 'file_name', and/or 'url' if present.
    Replaces Ruby's rb_easy_unescape.
    """
    for field in ["file_uri", "file_name", "url"]:
        val = event.get(field)
        if val and isinstance(val, str):
            try:
                unescaped = urllib.parse.unquote(val, encoding="utf-8", errors="replace")
                event.set(field, unescaped)
            except Exception:
                pass
    return event


def enrich_incident_scores(event, config=None):
    """
    Implements ips/98_incident_enrichment.conf:
    Computes malware_score from hash_score / ip_score / url_score,
    sets priority and message.
    """
    priority = "critical"
    if isinstance(config, dict) and "priority" in config:
        priority = config["priority"]

    hash_score = event.get("hash_score") or 0
    ip_score = event.get("ip_score") or 0
    url_score = event.get("url_score") or 0

    try:
        h_val = int(hash_score)
    except (ValueError, TypeError):
        h_val = 0

    try:
        i_val = int(ip_score)
    except (ValueError, TypeError):
        i_val = 0

    try:
        u_val = int(url_score)
    except (ValueError, TypeError):
        u_val = 0

    malware_score = 0
    if h_val > 0:
        malware_score += h_val
    elif i_val > 0:
        malware_score += i_val
    elif u_val > 0:
        malware_score += u_val

    message = f"Hash Score: {hash_score}, IP Score: {ip_score}, URL Score: {url_score}"

    event.set("malware_score", malware_score)
    event.set("priority", priority)
    event.set("message", message)
    return event


def filter(event, state=None):
    unescape_fields(event)
    return event
