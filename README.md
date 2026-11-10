# redborder-vortex

`redborder-vortex` is a high-performance, native Rust stream processing engine with an embedded Python (`pyo3`) plugin runtime designed as a drop-in replacement for Logstash on redBorder NG clusters.

It directly parses existing `/etc/logstash/pipelines.yml` and `/etc/logstash/pipelines/<name>/*.conf` Logstash DSL pipeline files while eliminating JVM startup overhead and heap footprint (~40 MB RSS vs. 1–4 GB on Logstash), achieving >200,000 events/sec per worker thread.

---

## Key Features

1. **Drop-in Logstash DSL Compatibility**:
   - Directly loads `/etc/logstash/pipelines.yml` and executes `input {}`, `filter {}`, and `output {}` stages from existing `.conf` files (`10_input_*.conf`, `20_filter_*.conf`, `30_output_*.conf`).
   - Full expression evaluator supporting nested conditionals (`if`, `else if`, `else`), comparisons (`==`, `!=`, `=~`, `!~`, `<`, `>`, `<=`, `>=`), membership checks (`in`, `not in`), boolean logic (`and`, `or`, `!`), and `[a][b][c]` bracket field path resolution.
2. **Multi-Cluster & Multi-Partition Coordination**:
   - **Kafka Consumer Groups**: Each pipeline acts as a coordinated Kafka consumer group (`group_id` per pipeline), automatically balancing partition assignments across all `redborder-vortex` nodes in the cluster and rebalancing on node failover.
   - **2-Tier L1 + L2 Shared State Store**: Combines a lock-free in-memory L1 cache (`DashMap`) for sub-microsecond hot reads with an asynchronous L2 Redis cluster backend (`redis::aio::ConnectionManager`) so enrichments learned on one node/partition (e.g., RADIUS sessions, NMSP/CMX wireless location, MAC vendor mappings) are immediately available across all cluster nodes.
   - **Distributed `rbwindow` Singleton Leader Lock**: Uses an atomic Redis lease (`SET rb:vortex:lock:rbwindow:<sensor_id> <node_id> NX EX 30`) so only the elected leader node emits periodic time-window events for a given sensor, failing over automatically within the lease TTL if the leader goes down.
3. **Native Rust Filters & Embedded Python (`pyo3`) Plugin SDK**:
   - All core Logstash filters (`mutate`, `cidr`, `geoip`, `grok`, `fingerprint`, `drop`) and custom redBorder plugins (`macscrambling`, `macvendorsenrich`, `netflowenrich`, `radius`, `nmsp`, `location`, `mobility`, `apstate`, `intrusion`, `device_enrichment`, `druid_metrics`, `threat_intelligence`, `incident_enrichment`) are compiled natively into Rust.
   - Existing Logstash `ruby { path => ... }` or `python { path => ... }` scripts (such as `malware`, `ips`, and `trap`) are transparently routed to an embedded Python 3 runtime via `pyo3` with zero-copy access to `PyEvent` and the 2-tier `PyStateStore`.
4. **Live IPC Socket & Telemetry (`redborder-monitor` style)**:
   - Exposes a non-blocking Unix Domain Socket (`/run/redborder-vortex/redborder-vortex.sock`) and CLI flags (`-t` / `--status`, `-r` / `--reset`) to inspect real-time per-pipeline throughput, event counters, drop counts, L1/L2 cache hit rates, and cluster leader state.

---

## Architecture Overview

```text
                       +---------------------------------------------------+
                       |                Kafka Cluster                      |
                       |  rb_flow, rb_sflow, rb_radius, rb_nmsp, rb_state  |
                       +-------------------------+-------------------------+
                                                 |
                         Consumer Group Rebalance| (Partition Assignment)
                       +-------------------------v-------------------------+
                       |                 redborder-vortex                  |
                       |                                                   |
  Unix Domain Socket   |  +---------------------------------------------+  |
 /var/run/redborder-   |  | Tokio Async Pipeline Workers (per pipeline) |  |
     vortex.sock <-----+--> 10_input -> 20_filter (AST) -> 30_output    |  |
  (status / reset)     |  +---------+-------------------------+---------+  |
                       |            |                         |            |
                       |  +---------v---------+     +---------v---------+  |
                       |  | Native Rust       |     | Embedded Python   |  |
                       |  | Filter Engine     |     | Runtime (PyO3)    |  |
                       |  +---------+---------+     +---------+---------+  |
                       |            |                         |            |
                       |  +---------v-------------------------v---------+  |
                       |  |       L1 Cache (In-Memory DashMap)          |  |
                       |  |   Sub-microsecond reads & TTL expiration    |  |
                       |  +----------------------+----------------------+  |
                       +-------------------------|-------------------------+
                                                 | L2 Read-Through / Write-Through
                                                 | + Distributed Leader Locks
                       +-------------------------v-------------------------+
                       |               Redis Cluster (L2)                  |
                       |   Shared Wireless / RADIUS / Flow State & Locks   |
                       +---------------------------------------------------+
```

---

## Configuration Guide

`redborder-vortex` uses a global daemon configuration file (`/etc/redborder-vortex/config.yml`) along with the standard Logstash pipeline definitions (`/etc/logstash/pipelines.yml`).

### 1. Service Configuration (`/etc/redborder-vortex/config.yml`)

```yaml
# redborder-vortex configuration
node_id: "auto"
pipelines_yml: "/etc/logstash/pipelines.yml"
socket_path: "/run/redborder-vortex/redborder-vortex.sock"
redis_url: "redis://127.0.0.1:6379"
python_plugins_dir: "/usr/share/redborder-vortex/plugins"
log_level: "info"

# NMSP In-Engine Triangulation (Weighted Centroid Localization without Cisco MSE/CMX)
nmsp.triangulation: false
nmsp.triangulation_min_aps: 2
```

* **Wireless Triangulation Options**:
  - `nmsp.triangulation` (or env `VORTEX_NMSP_TRIANGULATION`): Enables native multi-AP client triangulation using Weighted Centroid Localization ($w_i = 10^{\frac{\text{RSSI}_i}{20}}$) across APs on the same floor (default: `false`).
  - `nmsp.triangulation_min_aps` (or env `VORTEX_NMSP_TRIANGULATION_MIN_APS`): Minimum distinct APs required on the primary floor to triangulate (default: `2`). When fewer APs hear the client, coordinates fall back to the primary AP location.

### 2. Pipelines Definition (`/etc/logstash/pipelines.yml`)

`redborder-vortex` reads standard Logstash `pipelines.yml` entries (supporting wildcard globs in `path.config`):

```yaml
- pipeline.id: netflow
  path.config: "/etc/logstash/pipelines/netflow/*.conf"
  pipeline.workers: 2
  pipeline.batch.size: 125

- pipeline.id: sflow
  path.config: "/etc/logstash/pipelines/sflow/*.conf"
  pipeline.workers: 1

- pipeline.id: rbwindow
  path.config: "/etc/logstash/pipelines/rbwindow/*.conf"
  pipeline.workers: 1
```

---

## Supported Plugins Reference

### Built-in Logstash Filters (`src/filters/builtin.rs`)
- **`mutate`**: `rename`, `replace`, `add_field`, `remove_field`, `convert` (`integer`, `float`, `string`, `boolean`), `gsub`, `lowercase`, `uppercase`, `strip`, `split`, `join`, `merge`, `copy`, `add_tag`, `remove_tag`.
- **`cidr`**: IPv4 and IPv6 CIDR block matching (`address`, `network`, ` network_path`) with `add_field` / `add_tag` actions.
- **`geoip`**: Real MaxMind `.mmdb` database reader (`maxminddb`) for `City` and `ASN` lookups, with automatic fallback:
  - **City mode**: populates `[target][country_code2]`, `[target][country_name]`, `[target][continent_code]`, and `[target][city_name]`.
  - **ASN mode**: populates `[target][as_org]` and `[target][asn]`.
  - **Database resolution**:
    1. Explicit `database => "/path/to/custom.mmdb"` parameter if provided.
    2. Environment variables `GEOIP_CITY_DB`, `GEOIP_ASN_DB`, or `GEOIP_DB`.
    3. Standard system paths: `/var/lib/GeoIP/`, `/usr/share/GeoIP/`, `/etc/logstash/` (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`).
    4. Safe fallback for offline development / test environments without installed `.mmdb` files.
- **`grok`**: Regular expression & named pattern extraction (`%{SYNTAX:SEMANTIC}`).
- **`fingerprint`**: Deterministic hashing (`SHA1`, `SHA256`, `MD5`, `MURMUR3`) over source fields into a target field (including `@metadata` for Kafka partitioning).
- **`drop`**: Immediate or percentage-based event dropping.
- **`json`**: Parse JSON strings into nested structured objects or merge keys into root event (`source`, `target`). Adds `_jsonparsefailure` on invalid syntax.

### Native redBorder Filters (`src/filters/redborder.rs`)
- **`macscrambling`**: HMAC-SHA256 MAC address anonymization preserving the 24-bit OUI vendor prefix.
- **`macvendorsenrich`**: IEEE OUI database lookup enriching client and AP MAC vendor names.
- **`netflowenrich`**: Bidirectional NetFlow / IPFIX normalization, RFC1918 locality classification, IANA protocol resolution, and L1/L2 wireless session correlation.
- **`radius`**: Parses RADIUS Accounting (`Start`, `Interim-Update`, `Stop`) packets and updates shared L1/L2 client identity state (`username`, `calling_station_id`, `framed_ip_address`).
- **`nmsp`**: Cisco CMX / NMSP wireless telemetry enrichment (`dot11_status`, RSSI quality, configurable `client_profile` confidence thresholds: `soft_rssi`, `medium_rssi`, and native in-engine multi-AP Wi-Fi client triangulation via Weighted Centroid Localization without Cisco MSE/CMX hardware).
- **`mobility`**: Client movement, dwelling time, and session lifecycle tracking across `campus`, `building`, `floor`, and `zone` hierarchies with configurable timers (`consolidation_timer`, `expiration_timer`, `dwell_timer`), continuous static device tracking (`static` set to `0` when `dwell_time <= max_dwell_time` and `1` when `dwell_time > max_dwell_time`), and sliding TTL cache policies (`visitor_ttl` default 24h, `probe_ttl` default 2h for unconsolidated probe MACs) to prevent memory bloat while maintaining seamless dwell history.
- **`location` / `apstate`**: PostgreSQL nested-set spatial hierarchy enrichment and AP operational tracking backed by the L1/L2 `StateStore`. See [`FILTER.md`](FILTER.md) for full configuration reference.
- **`intrusion`**: Enriches IPS / Intrusion events from the shared L1/L2 `StateStore` (`sensor-psql`, `wlc-psql`, `nmsp-measure`, `nmsp-info`, `radius`, `location`, `dwell`, and `-historical` fallbacks).
- **`device_enrichment`**: Dual-mode ($O(1)$) network device metadata enrichment (`device_id`, `device_name`, `device_role`) by endpoint asset IP/MAC (`mode => "endpoint"`) or sensor association (`mode => "sensor"`), with configurable fallback, replacing static multi-thousand-line conditional Logstash blocks.
- **`druid_metrics` / `threat_intelligence` / `incident_enrichment`**: Real-time telemetry normalization and IOC matching.

### Not Yet Implemented (Legacy Filters)
- **`meraki`** (`logstash-filter-meraki`): Legacy Cisco Meraki CMX location/RSSI filter is not covered yet.
- **`postgrescve`** (`logstash-filter-postgrescve`): Legacy OpenVAS / vulnerability scanner PostgreSQL CVE enrichment filter is not covered yet.

### Embedded Python (`pyo3`) Plugin SDK (`src/filters/python.rs`)
Custom Python plugins live in `/usr/share/redborder-vortex/plugins/` (such as `malware.py`, `ips.py`, and `trap.py`) and implement `register(params)` and `filter(event, state)`:

```python
def register(params: dict) -> None:
    # Optional one-time plugin initialization
    pass

def filter(event, state=None) -> bool:
    """
    Mutate `event` in-place. Return True to keep the event, or False to drop it.
    `event` provides:
      - event.get("[field][subfield]") -> Any
      - event.set("[field][subfield]", value) -> None
      - event.remove("[field]") -> Any
      - event.tag("tag_name") -> None
      - event.to_dict() / event.from_dict(dict)
    `state` (optional PyStateStore) provides:
      - state.get(namespace, key) -> Any
      - state.set(namespace, key, value, ttl_secs) -> None
    """
    msg_type = event.get("[type]")
    if msg_type == "raw_counter":
        return False  # Drop event
    event.set("[enrichment][processed_by]", "vortex-python")
    return True
```

---

## Cluster Horizontal Scaling & Partition Keying

Vortex achieves seamless linear horizontal scaling across multiple nodes without race conditions or memory bloat by partitioning stateful mobility streams by `client_mac`.

### 1. Zero-Config Intermediate Topic Keying
Intermediate mobility topics (`rb_location` and `rb_mobility`) feeding stateful filters are automatically keyed by `client_mac`. Kafka's standard partitioner hashes all events for a given device into the same partition, guaranteeing that the exact same Vortex cluster node processes that device's lifecycle.
- **Traffic topics (`rb_flow`, `rb_sflow`, etc.)**: Remain unkeyed (round-robin) across all nodes.
- **Mobility state**: Strictly localized to the node consuming that partition, eliminating concurrent write-write races and Redis Pub/Sub flooding.

### 2. Configurable Topic Names & Custom Keys
Topic names and key fields are fully configurable:
* **In Pipeline Output Block (`output { kafka { ... } }`)**:
  - `message_key => "%{client_mac}"`: Explicit template interpolation.
  - `auto_key_topics => ["custom_location_topic"]`: List of topics to automatically key by MAC.
  - `auto_key_field => "sensor_mac"`: Custom field to use for auto-keying (default: `"client_mac"`).
* **In Global Daemon Config (`/etc/redborder-vortex/config.yml` or `path.settings`)**:
  ```yaml
  kafka.auto_key_mac_topics:
    - "rb_location"
    - "rb_mobility"
    - "custom_tenant_location"
  ```
* **Via Environment Variable**:
  ```bash
  export VORTEX_KAFKA_AUTO_KEY_MAC_TOPICS="rb_location,rb_mobility,custom_topic"
  ```

### 3. Cluster Partition Sizing & Reassignment
Partitions are configured during installation using `/usr/lib/redborder/scripts/rb_reassign_partitions.rb`:
```bash
/usr/lib/redborder/scripts/rb_reassign_partitions.rb -t rb_location -p 12 -n -e
```
* **Partition Recommendation**: Setting **12 partitions** (or at least **6**) allows seamless distribution across 1, 2, 3, 4, 6, or 12 nodes without needing to repartition when scaling nodes.

---

## CLI & IPC Socket Usage

### Command-Line Flags

```bash
# Run daemon with default configuration (/etc/redborder-vortex/config.yml)
redborder-vortex

# Run daemon with explicit config file or Logstash settings directory
redborder-vortex -c /etc/redborder-vortex/config.yml
redborder-vortex --path.settings /etc/logstash

# Validate pipelines.yml and all .conf files, then exit
redborder-vortex --config.test_and_exit --path.settings /etc/logstash

# Query live status of the running daemon via Unix socket
redborder-vortex -t
redborder-vortex --status

# Reset live pipeline counters via Unix socket
redborder-vortex -r
redborder-vortex --reset

# Check cluster node identity, Redis L2 connectivity, and L1/L2 cache stats
redborder-vortex --cluster-status

# Run built-in single-core pipeline throughput benchmark
redborder-vortex --benchmark
```

> **Note on `--benchmark` vs Production Daemon**:
> - **Production Daemon**: Dynamically parses `/etc/logstash/pipelines.yml` and all `.conf` pipeline definitions generated by Chef, connecting to live Kafka and Redis clusters.
> - **`--benchmark`**: A self-contained diagnostic tool that runs 50,000 synthetic events through representative in-memory NetFlow, sFlow, and Vault filter pipelines to benchmark raw throughput on developer or test machines without requiring installed `/etc/logstash` files, Kafka brokers, or Redis nodes.

### Querying the Unix Socket Directly

Like `redborder-monitor`, external scripts or monitoring agents can query `/run/redborder-vortex/redborder-vortex.sock` directly over a Unix domain stream socket using plain-text commands (`status`, `stats`, or `reset`):

```bash
$ echo "stats" | nc -U /run/redborder-vortex/redborder-vortex.sock
```

Example JSON response:
```json
{
  "node_id": "rb-node-01",
  "uptime_secs": 8420,
  "redis_connected": true,
  "l1_hits": 1482910,
  "l2_hits": 4219,
  "misses": 312,
  "pipelines": {
    "netflow": {
      "events_in": 942100,
      "events_out": 941850,
      "events_dropped": 250,
      "errors": 0,
      "workers": 2
    },
    "sflow": {
      "events_in": 128400,
      "events_out": 120110,
      "events_dropped": 8290,
      "errors": 0,
      "workers": 1
    }
  }
}
```

---

## Building & RPM Packaging

### Prerequisites
- Rust toolchain (`cargo`, `rustc` >= 1.75)
- `python3-devel` (`libpython3.9` on EL9) / `python3-dev` (Debian/Ubuntu)
- `openssl-devel` / `libssl-dev`, `libcurl-devel` / `libcurl4-openssl-dev`, `cmake`, `gcc`, `gcc-c++`, `make`
- `mock` and `rpm-build` (for building the EL9 RPM package)

### Build & Run Tests Locally

```bash
# Build release binary
make

# Run full unit and end-to-end test suite
make tests

# Run pipeline throughput benchmark
cargo run --release -- --benchmark
```

### Building the RPM with `mock`

The repository includes a standard redBorder `packaging/rpm` setup that vendors all Rust crates offline and builds a clean EL9 RPM inside a `mock` chroot (`rocky+epel-9-x86_64`):

```bash
# Build SRPM and binary RPM via mock
make rpm
# or directly:
make -C packaging/rpm rpm
```

Resulting packages are placed in `packaging/rpm/pkgs/`:
- `packaging/rpm/pkgs/redborder-vortex-<version>-1.el9.rb.src.rpm`
- `packaging/rpm/pkgs/redborder-vortex-<version>-1.el9.rb.x86_64.rpm`
