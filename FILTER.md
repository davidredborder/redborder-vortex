# redBorder Vortex - Filter & Plugin Reference Guide

This document provides a comprehensive guide to all native and extensible filters available in the **redBorder Vortex** telemetry and log pipeline engine.

---

## Table of Contents

- [Overview & Architecture](#overview--architecture)
- [1. Built-in Standard Filters](#1-built-in-standard-filters)
  - [`mutate`](#mutate)
  - [`grok`](#grok)
  - [`json`](#json)
  - [`geoip`](#geoip)
  - [`cidr`](#cidr)
  - [`fingerprint`](#fingerprint)
  - [`drop`](#drop)
- [2. redBorder Domain Filters](#2-redborder-domain-filters)
  - [`incident_enrichment`](#incident_enrichment)
  - [`threat_intelligence`](#threat_intelligence)
  - [`netflowenrich`](#netflowenrich)
  - [`macvendorsenrich`](#macvendorsenrich)
  - [`macscrambling`](#macscrambling)
  - [`druid_metrics`](#druid_metrics)
  - [`device_enrichment`](#device_enrichment)
  - [Wireless & Location Filters (`radius`, `nmsp`, `location`, `apstate`, `mobility`)](#wireless--location-filters)
- [3. Extensibility & Scripting Filters](#3-extensibility--scripting-filters)
  - [`python`](#python)
  - [`ruby` (Compatibility Layer)](#ruby-compatibility-layer)
  - [Special Aliased Plugins](#special-aliased-plugins)
  - [Unknown Plugin Fallback](#unknown-plugin-fallback)
- [4. Inputs & Outputs Reference](#4-inputs--outputs-reference)

---

## Overview & Architecture

Vortex executes Logstash-compatible configuration files (`*.conf`) with native compiled Rust filters for maximum throughput and near-zero memory allocation.

Filter statements in configuration files can be executed unconditionally or inside conditional expressions:

```ruby
filter {
  if [field_name] and [field_name] != "" {
    # filter block
  } else if "tag" in [tags] {
    # alternative filter
  } else {
    # default action
  }
}
```

> **Note on Truthiness:** Like Logstash, empty strings (`""`), `false`, and `null` evaluate to **falsy** in conditional checks `if [field]`.

---

## 1. Built-in Standard Filters

Source location: `src/filters/builtin.rs`

### `mutate`
Performs field transformations, renames, type conversions, string manipulations, and tag management.

**Supported Operations:**
- `add_field`: Adds new key-value pairs (supports `%{field}` string interpolation).
- `remove_field`: Removes specified fields.
- `rename`: Renames an existing field.
- `replace`: Replaces the value of an existing field.
- `convert`: Casts a field value (`integer`, `float`, `string`, `boolean`).
- `lowercase` / `uppercase`: Changes string case.
- `strip`: Trims leading and trailing whitespace.
- `split`: Splits a string into an array by delimiter.
- `join`: Joins an array into a single string by delimiter.
- `gsub`: Regex pattern substitution `[field, regex, replacement]`.
- `add_tag` / `remove_tag`: Appends or removes tags from the `tags` array.

**Example:**
```ruby
filter {
  mutate {
    rename => { "old_name" => "new_name" }
    add_field => {
      "target_endpoint" => "%{host}:%{port}"
      "cluster_environment" => "production"
    }
    convert => {
      "port" => "integer"
      "bytes" => "integer"
    }
    gsub => [ "url", " ", "%20" ]
    lowercase => [ "hostname" ]
    remove_field => [ "@timestamp", "raw_payload" ]
    add_tag => [ "normalized" ]
  }
}
```

---

### `grok`
Parses unstructured log lines into structured fields using regular expressions and reusable pattern files.

**Supported Settings:**
- `match`: Map of field names to grok pattern expressions.
- `patterns_dir`: Directory containing custom grok pattern definition files.
- `overwrite`: List of fields that are permitted to overwrite existing fields.
- `tag_on_failure`: Tag added to the event if parsing fails (defaults to `["_grokparsefailure"]`).

**Example:**
```ruby
filter {
  grok {
    patterns_dir => ["/etc/logstash/pipelines/vault/patterns"]
    match => {
      "message" => [
        "%{IPTABLES_MESSAGE}",
        "%{SSHD_MESSAGE}",
        "%{NGINXACCESS}"
      ]
    }
    tag_on_failure => ["_grokfailure"]
  }
}
```

---

### `json`
Parses a JSON string field into an object or merges its keys into the event root.

**Supported Settings:**
- `source`: Field name containing the raw JSON string.
- `target`: Target field to store the parsed object. If omitted, fields are merged directly into the event root.

**Example:**
```ruby
filter {
  json {
    source => "raw_json_message"
    target => "parsed_data"
  }
}
```

---

### `geoip`
Looks up geographic information and Autonomous System Numbers (ASN) for IP addresses using MaxMind GeoIP2 / GeoLite2 databases.

**Supported Settings:**
- `source`: IP address field to look up.
- `target`: Destination container field (defaults to `geoip`).
- `database`: Path to `.mmdb` file (default: `/var/lib/GeoIP/GeoLite2-City.mmdb` or `/var/lib/GeoIP/GeoLite2-ASN.mmdb`).
- `fields`: Specific fields to extract (`country_code2`, `country_name`, `city_name`, `latitude`, `longitude`, `as_org`, `as_num`).

**Example:**
```ruby
filter {
  geoip {
    source => "src_ip"
    target => "city_lan"
    fields => ["country_code2", "city_name", "as_org"]
    database => "/var/lib/GeoIP/GeoLite2-City.mmdb"
  }
}
```

---

### `cidr`
Evaluates IP addresses against a list of CIDR subnet masks and applies tags or fields on match.

**Supported Settings:**
- `address`: List of fields containing the IP address to evaluate.
- `network`: List of CIDR subnets (e.g. `10.0.0.0/8`, `192.168.0.0/16`).
- `add_tag`: Tags to add when an IP matches the CIDR range.
- `add_field`: Fields to set when an IP matches.

**Example:**
```ruby
filter {
  cidr {
    address => [ "%{src_ip}" ]
    network => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ]
    add_tag => [ "is_src_internal" ]
    add_field => { "traffic_direction" => "lan_to_wan" }
  }
}
```

---

### `fingerprint`
Calculates cryptographic hash fingerprints of one or more fields.

**Supported Settings:**
- `source`: Field name (or list of fields) to hash.
- `target`: Output field name (defaults to `fingerprint`).
- `method`: Hash algorithm (`SHA256`, `MD5`, `SHA1`, `SHA384`, `SHA512`).
- `key`: Optional HMAC secret key.

**Example:**
```ruby
filter {
  fingerprint {
    source => "raw-message"
    target => "fingerprint"
    method => "SHA256"
    key => "cluster_enterprise_key"
  }
}
```

---

### `drop`
Immediately cancels the event and prevents it from being passed to subsequent filters or output sinks.

**Example:**
```ruby
filter {
  if [discard] and [discard] == "true" {
    drop {}
  }
}
```

---

## 2. redBorder Domain Filters

Source location: `src/filters/redborder.rs`

### `incident_enrichment`
Correlates incoming security events with the redBorder Alarm & Incident system:
- Looks up existing incidents in Redis by correlation keys (`rbincident(:<ns>):incident:<uuid>`).
- If no existing incident matches, allocates a new incident UUID.
- Records TTL correlation keys (600s) and relation tracking keys (`rbincident:relation:<uuid>`).
- Computes aggregate incident scores and formats ISO-8601 `first_event_at` timestamps for `redborder-mem2incident`.

**Supported Settings:**
- `source`: Incident source identifier (e.g., `Vault`, `Malware`, `IPS`).
- `incident_fields`: Fields used to form correlation keys (e.g., `["fromhost_ip"]` or `["sha256", "filename"]`).
- `incidents_priority_filter`: Minimum priority threshold (e.g. `error`, `critical`).
- `field_scores`: Map of field names to their score weight.
- `field_map`: Normalization aliases for field names.
- `malware_score_threshold`: Threshold score required to trigger incident correlation.
- `redis_hosts`: Redis cluster / standalone hostnames.
- `redis_port`: Redis port (default: 6379 or Sentinel 26379).
- `redis_password`: Redis authentication password.
- `cache_expiration`: Cache TTL in seconds (default: 600).

**Example:**
```ruby
filter {
  if ![incident_uuid] {
    incident_enrichment {
      source => "Vault"
      incident_fields => ["fromhost_ip"]
      incidents_priority_filter => "error"
      field_scores => {
        "fromhost_ip" => 100
      }
      field_map => {
        "fromhost_ip" => "ip"
      }
      redis_hosts => ["rb-cluster-redis"]
      redis_port => 6379
      redis_password => "vault_secret"
      cache_expiration => 600
    }
  }
}
```

---

### `threat_intelligence`
Enriches network traffic and logs with Threat Intelligence IOCs (Indicators of Compromise), querying Memcached and Redis caches populated by redBorder TI feeds.

**Supported Settings:**
- `memcached_servers`: List of Memcached host/port endpoints (`host:port`).
- `sensor_nodes`: List of sensor node IP addresses to apply TI policies against.

**Example:**
```ruby
filter {
  threat_intelligence {
    memcached_servers => ["127.0.0.1:11211"]
    sensor_nodes => ["192.0.2.20"]
  }
}
```

---

### `netflowenrich`
High-throughput flow enrichment filter for NetFlow / IPFIX / sFlow traffic:
- Performs 180-second active flow duration splitting.
- Calculates bidirectional flow indicators (`biflow_direction`).
- Normalizes layer-4 protocols (`TCP`, `UDP`, `ICMP`) and well-known application IDs.

**Example:**
```ruby
filter {
  netflowenrich {}
}
```

---

### `macvendorsenrich`
Enriches MAC addresses with hardware manufacturer names using IEEE OUI tables.

**Supported Settings:**
- `source`: Field name containing the MAC address (default: `client_mac`).
- `target`: Field name to store the vendor name (default: `client_mac_vendor`).

**Example:**
```ruby
filter {
  macvendorsenrich {
    source => "client_mac"
    target => "client_mac_vendor"
  }
}
```

---

### `macscrambling`
Cryptographically hashes/anonymizes MAC addresses for privacy compliance (GDPR) while preserving unique identifiers for analytics.

**Supported Settings:**
- `fields`: List of fields to scramble (default: `["client_mac"]`).
- `salt`: Custom salt string (optional).

**Example:**
```ruby
filter {
  macscrambling {
    fields => ["client_mac", "wireless_station"]
  }
}
```

---

### `druid_metrics`
Translates operational metrics emitted by Apache Druid (`druid-kafka-emitter`) into normalized `rb_monitor` telemetry events:
- Maps query latency, query counts, cache hit ratios, and segment metrics to standard names.
- Converts timestamps to UNIX epoch seconds.
- Normalizes hostname and sensor identifiers.

**Example:**
```ruby
filter {
  druid_metrics {}
}
```

---

### `device_enrichment`
Enriches events with network device metadata based on endpoint assets (IP/MAC) or sensor associations.

Vortex continuously synchronizes devices, interfaces, IP addresses (`ipam_ip_addresses`), MAC addresses (`macaddresses`), device roles, and sensor links from PostgreSQL into the internal `StateStore` (`DEVICE_IP_PSQL_STORE`, `DEVICE_MAC_PSQL_STORE`, and `SENSOR_PSQL_STORE`).

#### Configuration Options

- `mode` (string, optional, default: `"endpoint"`):
  - `"endpoint"`: Resolves devices using endpoint IP addresses (`lan_ip`, `wan_ip`, `src_ip`, `dst_ip`) and endpoint MAC addresses (`client_mac`, `server_mac`, `mac`). Transit infrastructure MAC addresses (e.g. routers, switches, firewalls) are ignored so transit traffic is attributed to the real host/asset (e.g. NAS, server) rather than the router.
  - `"sensor"`: Resolves devices based on the `sensor_uuid` (used for pipeline types like vault and monitor where events are directly generated by the sensor).
  - `"auto"`: Dynamically detects whether endpoint fields exist; if none exist, uses sensor resolution.
- `fallback_to_sensor` (boolean, optional, default: `false`):
  - When `true`: If endpoint IP and MAC resolution yields no device match, falls back to resolving `sensor_uuid`.
  - When `false`: Leaves `device_id` unassigned (`N/A`) if endpoint resolution yields no match, preventing unmanaged transit flows from being falsely attributed to the transit router.

When a device is matched, `device_enrichment` populates:
- `device_id`: Device identifier (e.g., `"42"`).
- `device_name`: Configured device name (e.g., `"nas-storage-01"`).
- `device_role`: Device classification or role (e.g., `"NAS"`, `"Server"`, `"Router"`).

Existing event attributes are preserved and not overwritten.

**Example (NetFlow Pipeline - Endpoint Mode):**
```ruby
filter {
  device_enrichment {
    mode => "endpoint"
    fallback_to_sensor => false
  }
}
```

**Example (Vault / Monitor Pipeline - Sensor Mode):**
```ruby
filter {
  device_enrichment {
    mode => "sensor"
    fallback_to_sensor => true
  }
}
```

---

### Wireless & Location Filters

#### `nmsp`
Cisco Network Mobility Services Protocol (NMSP) and wireless measure/info telemetry processor. Enriches events with Access Point association status (`dot11_status`), RSSI classification (`client_rssi`, `client_rssi_num`), and detection confidence profile (`client_profile`).

**Client Profile Classification:**
Determines client detection confidence based on Wi-Fi signal strength (RSSI in dBm) or association state:
* **`hard`**: `RSSI > medium_rssi` (or `RSSI == 0`, e.g. Cisco MSE / RADIUS / Associated). High confidence / accurate location close to AP.
* **`medium`**: `soft_rssi < RSSI <= medium_rssi`. Medium confidence / reasonable signal.
* **`soft`**: `RSSI <= soft_rssi`. Low confidence / fringe probes detected at the edge of AP coverage.

**Supported Settings:**
* `soft_rssi` / `profile_soft_rssi` / `soft_threshold`: RSSI threshold for soft profile (default: `-75` dBm).
* `medium_rssi` / `profile_medium_rssi` / `medium_threshold`: RSSI threshold for medium profile (default: `-65` dBm).
* `rssi_bad`: Threshold for "bad" signal quality (default: `-85` dBm).
* `rssi_low`: Threshold for "low" signal quality (default: `-80` dBm).
* `rssi_medium`: Threshold for "medium" signal quality (default: `-70` dBm).
* `rssi_good`: Threshold for "good" signal quality (default: `-60` dBm).
* `triangulation` / `enable_triangulation`: Enable native multi-AP client triangulation using Weighted Centroid Localization (default: `false`). Can also be configured globally via `nmsp.triangulation: true` in `/etc/redborder-vortex/config.yml` or `VORTEX_NMSP_TRIANGULATION=true`.
* `triangulation_min_aps` / `min_aps`: Minimum number of distinct APs on the same floor required to trigger triangulation (default: `2`). If fewer APs detect the client, coordinates fall back to the primary AP location. Can also be set via `nmsp.triangulation_min_aps: 2` or `VORTEX_NMSP_TRIANGULATION_MIN_APS=2`.

**Native Multi-AP Client Triangulation:**
When raw WLC `measure` messages arrive without an external Cisco MSE / CMX location engine, Vortex can calculate client coordinates natively using Weighted Centroid Localization:
1. Filters AP measurements to only those sharing the same `floor_uuid` as the primary (strongest) AP to prevent multi-floor vertical distortion.
2. Deduplicates dual-band radio reports per physical AP MAC, retaining the strongest RSSI reading.
3. Computes linear signal weight for each AP:
   $$w_i = 10^{\frac{\text{RSSI}_i}{20}}$$
4. Calculates blended client coordinates:
   $$\text{lat} = \frac{\sum w_i \cdot \text{lat}_i}{\sum w_i}, \quad \text{lon} = \frac{\sum w_i \cdot \text{lon}_i}{\sum w_i}$$
5. Enriches the event with `client_latlong: "lat,lon"` and `triangulation_aps: N` (number of participating APs).
6. If the number of APs on the floor is below `triangulation_min_aps`, the calculation safely falls back directly to the primary AP's coordinates.

**Example:**
```ruby
filter {
  nmsp {
    soft_rssi => -75
    medium_rssi => -65
    triangulation => true
    triangulation_min_aps => 2
  }
}
```

---

#### `mobility`
Real-time tracking of client location movements, dwelling times, and session lifecycles across full organizational and spatial hierarchies (`campus`, `building`, `floor`, `zone`).

**Emitted Events:**
* **Static Presence (`transition: 0`)**: Emitted once per minute while client dwells in the same location up to `max_dwell_time`.
* **Roaming Movement (`transition: 1`)**: Emitted upon transitioning between locations (`old` -> `new`), e.g. moving between floors or zones.
* **Entry Movement (`transition: 1`)**: Emitted when entering from `outside` to a location (`old: "outside"`, `new: "<uuid>"`).
* **Exit Movement (`transition: 1`)**: Emitted when a client's session expires due to inactivity (`old: "<uuid>"`, `new: "outside"`).
* **Hierarchy Coverage**: Simultaneously emits tracking events for each hierarchy tier (`campus`, `building`, `floor`, and `zone`).
* **Profile Inheritance**: Forwards `client_profile` from upstream filters (defaulting to `"hard"` if missing) ensuring compatibility with web UI queries.

**Supported Settings (with convenient aliases):**
* `consolidated_time` / `consolidation_time` / `consolidation_timer`: Seconds a client must remain at a new location before a movement is consolidated (default: `180` seconds / 3 min).
* `expired_time` / `expiration_time` / `expiration_timer`: Inactivity timeout in seconds before a client session expires and an exit to `outside` is generated (default: `1800` seconds / 30 min).
* `max_dwell_time` / `dwell_timer`: Maximum static presence events emitted before dwell time caps (default: `1440` minutes / 24 hours).
* `expired_repetitions_time` / `repetitions_expiration_timer`: Inactivity duration in seconds before visit repetition counts reset (default: `86400` seconds / 24 hours).
* `max_time_without_movement` / `visitor_ttl` / `client_ttl` / `max_ttl`: Sliding TTL in seconds for consolidated / active visitors in the mobility state store before eviction (default: `86400` seconds / 24 hours).
* `probe_ttl` / `outside_ttl` / `ephemeral_ttl`: Sliding TTL in seconds for unconsolidated / outside probe devices to prevent memory bloat from transient passer-by MACs (default: `7200` seconds / 2 hours).
* `dwell_ttl` / `dwell_store_ttl`: Retention time in seconds for dwell records (default: `86400` seconds / 24 hours).

**Sliding Eviction & State Retention:**
Rather than wiping stores periodically (which caused graph drops in earlier versions), `mobility` uses continuous sliding-window TTL eviction. Active visitors renewing their presence retain their session history, while ephemeral Wi-Fi probes expire smoothly after `probe_ttl`.

**Example:**
```ruby
filter {
  mobility {
    consolidation_timer => 180
    expiration_timer => 1800
    dwell_timer => 86400
    visitor_ttl => 86400
    probe_ttl => 7200
  }
}
```

---

#### Other Wireless Filters
* **`radius`**: Parses RADIUS access requests and accounting attributes (username, NAS IP, framed IP) into the shared state store.
* **`location`**: Coordinates, geofences, campus, building, and floor spatial enrichment via PostgreSQL nested sets.
* **`apstate`**: Access point operational state tracking and heartbeat monitoring.

---

## 3. Extensibility & Scripting Filters

Source location: `src/filters/python.rs`

For business logic requiring custom code, Vortex provides PyO3-backed zero-copy Python execution.

### `python`
Executes custom Python modules or inline code.

**Supported Settings:**
- `module`: Name of the Python module located in the plugins directory (e.g. `/usr/share/redborder-vortex/plugins/` or `plugins/`).
- `function`: Specific function inside the module to call (default: `filter`).
- `config`: A map of key-value pairs passed as a Python dictionary.
- `init`: Startup Python code run once during initialization.
- `code`: Inline Python code executed per event.

#### Method 1: External Python Module with Configuration
```ruby
filter {
  python {
    module => "ips"
    function => "enrich_incident_scores"
    config => {
      "priority" => "critical",
      "threshold" => 50
    }
  }
}
```

Corresponding Python function signature (`plugins/ips.py`):
```python
def enrich_incident_scores(event, config=None):
    priority = config.get("priority", "low") if config else "low"
    event.set("priority", priority)
    return event
```

#### Method 2: Inline Python Code
```ruby
filter {
  python {
    init => 'import math'
    code => '
      val = event.get("raw_val")
      if val is not None:
          event.set("calc_val", math.sqrt(float(val)))
    '
  }
}
```

---

### `ruby` (Legacy Compatibility Shim)

> [!WARNING]
> **Not a native Ruby / JRuby runtime.** Vortex embeds Python (via PyO3) and does not bundle a JVM or Ruby interpreter. 
> 
> The `ruby { ... }` block is a **lightweight transpilation shim** designed solely to keep legacy, unmigrated Logstash configurations working without syntax errors.

#### How It Works:
Vortex's transpiler (`translate_ruby_to_python` in `src/filters/python.rs`) parses the Ruby snippet at startup and maps standard Logstash Ruby idioms into equivalent Python code, which is then executed inside the embedded Python runtime:
- `event.get('field')` $\rightarrow$ `event.get('field')`
- `event.set('field', val)` $\rightarrow$ `event.set('field', val)`
- `event.tag('tag_name')` $\rightarrow$ `event.tag('tag_name')`
- `IPAddr.new("10.0.0.0/8")` $\rightarrow$ `ipaddress.ip_network("10.0.0.0/8")`
- Ruby blocks like `if ... else ... end` are converted to Python indent blocks.

#### Supported Example:
```ruby
filter {
  ruby {
    init => '
      require "ipaddr"
      NET = IPAddr.new("10.0.0.0/8")
    '
    code => '
      ip = event.get("src_ip")
      if ip and NET.include?(IPAddr.new(ip))
        event.tag("internal")
      end
    '
  }
}
```

#### Limitations & Best Practices:
- Complex Ruby gems, metaprogramming, classes, or advanced standard library methods outside basic Logstash operations are **not supported**.
- **Do not write new `ruby` blocks.** For any new custom pipeline logic, write native Rust filters (for peak performance) or use [`python { ... }`](#python).

---

### Special Aliased Plugins
For seamless backward compatibility with existing Logstash cookbooks, the following legacy plugins automatically route to `plugins/malware.py`:
- `yara` $\rightarrow$ `python { module => "malware", function => "yara_scan" }`
- `aerospike-malware-score` $\rightarrow$ `python { module => "malware", function => "aerospike_malware_score" }`
- `s3-upload-malware-results` $\rightarrow$ `python { module => "malware", function => "s3_upload_malware_results" }`

---

### Unknown Plugin Fallback
If a filter block name in a `.conf` file is not recognized (for example, a disabled plugin or obsolete filter), Vortex handles it safely with `NoopFilter`. It logs a debug notice and continues passing events through the pipeline without crashing or stalling.

---

## 4. Inputs & Outputs Reference

Source locations: `src/inputs/` and `src/outputs/`

### Input: `kafka`
```ruby
input {
  kafka {
    bootstrap_servers => "kafka.service:9092"
    topics => ["rb_flow"]
    group_id => "redborder-vortex-netflow-pipeline"
    codec => json
    consumer_threads => 3
    auto_offset_reset => "latest"
  }
}
```

### Input: `rbwindow`
Sliding and tumbling window accumulator for real-time aggregations:
```ruby
input {
  rbwindow {
    schedule => "*/1 * * * *"
    step => 60
    window => 300
    metrics => ["bytes", "packets"]
    dimensions => ["sensor_name", "src_ip"]
    output_topic => "rb_flow_aggregated"
  }
}
```

### Input: `pipeline` (In-Memory Virtual Queue)
Receives events directly in-memory from another pipeline without publishing to Kafka:
```ruby
input {
  pipeline {
    address => "netflow-pipeline"  # Unique virtual address identifier
  }
}
```

### Output: `kafka`
```ruby
output {
  kafka {
    bootstrap_servers => "kafka.service:9092"
    topic_id => "rb_flow_post"
    codec => json
  }
}
```

### Output: `pipeline` (In-Memory Virtual Queue)
Streams events directly into the in-memory queue of one or more downstream pipelines:
```ruby
output {
  pipeline {
    send_to => ["netflow-pipeline"]  # Target address or pipeline ID
  }
}
```

### Output: `stdout`
Useful for local debugging and CLI pipeline testing:
```ruby
output {
  stdout {
    codec => rubydebug  # or json
  }
}
```
