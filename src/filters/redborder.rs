use crate::config::ast::PluginBlock;
use crate::event::Event;
use crate::filters::Filter;
use crate::state::{
    StateStore, COUNTER_STORE, DEVICE_IP_PSQL_STORE, DEVICE_MAC_PSQL_STORE, DWELL_STORE,
    LOCATION_STORE, MOBILITY_STORE, NMSP_STORE_INFO, NMSP_STORE_MEASURE, RADIUS_STORE,
    SCRAMBLES_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::fs;
use std::path::Path;

const DEFAULT_MAC_PREFIX: &str = "fdah7usad782345@";
const DEFAULT_MAC_VENDORS_PATH: &str = "/etc/objects/mac_vendors";

fn event_i64(event: &Event, key: &str) -> Option<i64> {
    match event.get(key)? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s
            .parse::<i64>()
            .ok()
            .or_else(|| s.parse::<f64>().ok().map(|f| f as i64)),
        _ => None,
    }
}

fn event_f64(event: &Event, key: &str) -> Option<f64> {
    match event.get(key)? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn normalize_mac(mac: &str) -> String {
    mac.trim().to_lowercase().replace('-', ":")
}

#[derive(Debug, Clone, Default)]
pub struct MacScramblingFilter;

impl MacScramblingFilter {
    pub fn new() -> Self {
        Self
    }

    pub fn from_block(_block: &PluginBlock) -> Self {
        Self
    }
}

impl Filter for MacScramblingFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let Some(sp_uuid) = event.get_str("service_provider_uuid") else {
            return Ok(vec![event]);
        };
        let Some(client_mac) = event.get_str("client_mac") else {
            return Ok(vec![event]);
        };
        let Some(scramble_record) = state.get_record(SCRAMBLES_STORE, &sp_uuid) else {
            return Ok(vec![event]);
        };
        let Some(salt) = scramble_record
            .get("mac_hashing_salt")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        else {
            return Ok(vec![event]);
        };

        let mac_prefix = scramble_record
            .get("mac_prefix")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_MAC_PREFIX);

        let input = format!("{}{}{}", mac_prefix, client_mac.to_lowercase(), salt);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let digest = hasher.finalize();
        let scrambled = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
        );
        event.set("client_mac", scrambled);
        Ok(vec![event])
    }
}

#[derive(Debug, Clone)]
pub struct MacVendorsEnrichFilter {
    pub vendors: HashMap<String, String>,
}

impl Default for MacVendorsEnrichFilter {
    fn default() -> Self {
        Self::new(Some(DEFAULT_MAC_VENDORS_PATH))
    }
}

impl MacVendorsEnrichFilter {
    pub fn new(path: Option<&str>) -> Self {
        let mut vendors = HashMap::new();
        vendors.insert("00000C".to_string(), "Cisco Systems, Inc".to_string());
        vendors.insert("AABBCC".to_string(), "Test Vendor".to_string());

        let file_path = path.unwrap_or(DEFAULT_MAC_VENDORS_PATH);
        if Path::new(file_path).exists() {
            if let Ok(content) = fs::read_to_string(file_path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if let Some((oui, vendor)) = trimmed.split_once('|') {
                        let normalized_oui: String = oui
                            .chars()
                            .filter(|c| *c != ':' && *c != '-' && !c.is_whitespace())
                            .collect::<String>()
                            .to_uppercase();
                        if normalized_oui.len() >= 6 {
                            vendors.insert(
                                normalized_oui[..6].to_string(),
                                vendor.trim().to_string(),
                            );
                        }
                    }
                }
            }
        }

        Self { vendors }
    }

    pub fn with_vendors(vendors: HashMap<String, String>) -> Self {
        Self { vendors }
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        Self::new(block.get_str("path"))
    }
}

impl Filter for MacVendorsEnrichFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        if event.contains("client_mac_vendor") {
            return Ok(vec![event]);
        }
        let Some(mac) = event.get_str("client_mac") else {
            return Ok(vec![event]);
        };
        let cleaned: String = mac
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(6)
            .collect::<String>()
            .to_uppercase();
        if cleaned.len() == 6 {
            if let Some(vendor) = self.vendors.get(&cleaned) {
                event.set("client_mac_vendor", vendor.clone());
            }
        }
        Ok(vec![event])
    }
}

#[derive(Debug, Clone)]
pub struct NetflowEnrichFilter {
    pub counter_store_counter: bool,
}

impl Default for NetflowEnrichFilter {
    fn default() -> Self {
        Self {
            counter_store_counter: true,
        }
    }
}

impl NetflowEnrichFilter {
    pub fn new(counter_store_counter: bool) -> Self {
        Self {
            counter_store_counter,
        }
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        let counter_store_counter = block
            .get_setting("counter_store_counter")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        Self {
            counter_store_counter,
        }
    }
}

impl Filter for NetflowEnrichFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        // 1. Enrich from StateStore
        state.enrich(&mut event);

        // 2. Calculate duration
        let ts_opt = event_i64(&event, "timestamp");
        let fs_opt = event_i64(&event, "first_switched");

        if let (Some(ts), Some(fs)) = (ts_opt, fs_opt) {
            let duration = (ts - fs).max(0);
            event.set("duration", duration);
        }

        // 3. Split flow across 60-second minute boundaries
        let splitted_events = match (fs_opt, ts_opt) {
            (Some(packet_start), Some(packet_end)) if packet_end > packet_start => {
                let total_diff = packet_end - packet_start;
                let total_bytes = event_i64(&event, "bytes").unwrap_or(0);
                let total_pkts = event_i64(&event, "pkts").unwrap_or(0);
                let has_pkts = event.contains("pkts");

                let mut slices = Vec::new();
                let mut this_start = packet_start;
                while this_start < packet_end {
                    let rem = this_start.rem_euclid(60);
                    let this_end = (this_start + (60 - rem)).min(packet_end);
                    slices.push((this_start, this_end));
                    this_start = this_end;
                }

                let mut events = Vec::with_capacity(slices.len());
                let mut acc_bytes: i64 = 0;
                let mut acc_pkts: i64 = 0;
                let num_slices = slices.len();

                for (idx, (s_start, s_end)) in slices.into_iter().enumerate() {
                    let diff = s_end - s_start;
                    let (slice_bytes, slice_pkts) = if idx + 1 == num_slices {
                        (
                            (total_bytes - acc_bytes).max(0),
                            (total_pkts - acc_pkts).max(0),
                        )
                    } else {
                        let b = (((total_bytes as f64) * (diff as f64) / (total_diff as f64)).ceil()
                            as i64)
                            .min((total_bytes - acc_bytes).max(0));
                        let p = (((total_pkts as f64) * (diff as f64) / (total_diff as f64)).ceil()
                            as i64)
                            .min((total_pkts - acc_pkts).max(0));
                        acc_bytes += b;
                        acc_pkts += p;
                        (b, p)
                    };

                    let mut overrides = Map::new();
                    overrides.insert("timestamp".to_string(), json!(s_start));
                    overrides.insert("bytes".to_string(), json!(slice_bytes));
                    if has_pkts {
                        overrides.insert("pkts".to_string(), json!(slice_pkts));
                    }

                    let removed: &[&str] = if idx > 0 {
                        &["first_switched", "duration"]
                    } else {
                        &["first_switched"]
                    };

                    events.push(event.clone_with_overrides(overrides, removed));
                }
                events
            }
            (_, Some(_)) => {
                if let Some(b) = event_i64(&event, "bytes") {
                    event.set("bytes", b);
                }
                if let Some(p) = event_i64(&event, "pkts") {
                    event.set("pkts", p);
                }
                event.remove("first_switched");
                vec![event]
            }
            _ => vec![event],
        };

        // 4. Increment counterStore if enabled
        if self.counter_store_counter {
            let count = splitted_events.len() as i64;
            state.increment_counter(COUNTER_STORE, "rb_flow", count)?;
            if let Some(ns) = splitted_events
                .first()
                .and_then(|e| e.get_str("namespace_uuid"))
                .filter(|s| !s.is_empty())
            {
                state.increment_counter(COUNTER_STORE, &format!("rb_flow_{}", ns), count)?;
            }
        }

        Ok(splitted_events)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RadiusFilter;

impl RadiusFilter {
    pub fn new() -> Self {
        Self
    }

    pub fn from_block(_block: &PluginBlock) -> Self {
        Self
    }
}

fn parse_called_station_id(called: &str) -> (String, Option<String>) {
    let trimmed = called.trim();
    if trimmed.len() >= 17 {
        let bytes = trimmed.as_bytes();
        let is_sep = |b: u8| b == b':' || b == b'-';
        if is_sep(bytes[2])
            && is_sep(bytes[5])
            && is_sep(bytes[8])
            && is_sep(bytes[11])
            && is_sep(bytes[14])
        {
            let ap_mac = normalize_mac(&trimmed[..17]);
            let ssid = if trimmed.len() > 18 && bytes[17] == b':' {
                Some(trimmed[18..].to_string())
            } else {
                None
            };
            return (ap_mac, ssid);
        }
    }
    if let Some((mac_part, ssid_part)) = trimmed.split_once(':') {
        return (
            normalize_mac(mac_part),
            if ssid_part.is_empty() {
                None
            } else {
                Some(ssid_part.to_string())
            },
        );
    }
    (normalize_mac(trimmed), None)
}

impl Filter for RadiusFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let Some(calling_id) = event
            .get_str("Calling-Station-Id")
            .filter(|s| !s.trim().is_empty())
        else {
            event.cancel();
            return Ok(vec![]);
        };

        let client_mac = normalize_mac(&calling_id);
        event.set("client_mac", client_mac.clone());

        if let Some(src_ip) = event.get_str("Packet-Src-IP-Address") {
            event.set("sensor_ip", src_ip);
        }

        let mut to_cache = Map::new();

        if let Some(user) = event.get_str("User-Name") {
            to_cache.insert("client_id".to_string(), Value::String(user));
        }
        if let Some(op) = event.get_str("Operator-Name") {
            to_cache.insert("wireless_operator".to_string(), Value::String(op));
        }
        if let Some(wlan_id) = event.get_str("Airespace-Wlan_Id") {
            to_cache.insert("wireless_id".to_string(), Value::String(wlan_id));
        }
        if let Some(acct_type) = event.get_str("Acct-Status-Type") {
            to_cache.insert(
                "client_accounting_type".to_string(),
                Value::String(acct_type.to_lowercase()),
            );
        }
        if let Some(called_id) = event.get_str("Called-Station-Id") {
            let (ap_mac, ssid) = parse_called_station_id(&called_id);
            if !ap_mac.is_empty() {
                to_cache.insert("wireless_station".to_string(), Value::String(ap_mac));
            }
            if let Some(ssid_val) = ssid {
                to_cache.insert("wireless_id".to_string(), Value::String(ssid_val));
            }
        }

        let ns = event.get_str("namespace_uuid").unwrap_or_default();
        let store_key = format!("{}{}", client_mac, ns);
        state.put_record(RADIUS_STORE, &store_key, to_cache.clone())?;

        event.set("type", "radius");
        event.set("client_profile", "hard");
        for (k, v) in to_cache {
            event.set(&k, v);
        }

        state.enrich(&mut event);
        Ok(vec![event])
    }
}

pub const DEFAULT_SOFT_RSSI: i64 = -75;
pub const DEFAULT_MEDIUM_RSSI: i64 = -65;
pub const DEFAULT_RSSI_BAD: i64 = -85;
pub const DEFAULT_RSSI_LOW: i64 = -80;
pub const DEFAULT_RSSI_MEDIUM: i64 = -70;
pub const DEFAULT_RSSI_GOOD: i64 = -60;

#[derive(Debug, Clone)]
pub struct NmspFilter {
    pub soft_rssi: i64,
    pub medium_rssi: i64,
    pub rssi_bad: i64,
    pub rssi_low: i64,
    pub rssi_medium: i64,
    pub rssi_good: i64,
    pub enable_triangulation: bool,
    pub triangulation_min_aps: usize,
}

impl Default for NmspFilter {
    fn default() -> Self {
        Self {
            soft_rssi: DEFAULT_SOFT_RSSI,
            medium_rssi: DEFAULT_MEDIUM_RSSI,
            rssi_bad: DEFAULT_RSSI_BAD,
            rssi_low: DEFAULT_RSSI_LOW,
            rssi_medium: DEFAULT_RSSI_MEDIUM,
            rssi_good: DEFAULT_RSSI_GOOD,
            enable_triangulation: std::env::var("VORTEX_NMSP_TRIANGULATION")
                .map(|v| v == "true" || v == "1" || v == "yes")
                .unwrap_or(false),
            triangulation_min_aps: std::env::var("VORTEX_NMSP_TRIANGULATION_MIN_APS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2)
                .max(2),
        }
    }
}

impl NmspFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        let mut filter = Self::default();
        if let Some(v) = block
            .get_setting("soft_rssi")
            .or_else(|| block.get_setting("profile_soft_rssi"))
            .or_else(|| block.get_setting("soft_threshold"))
            .and_then(|v| v.as_i64())
        {
            filter.soft_rssi = v;
        }
        if let Some(v) = block
            .get_setting("medium_rssi")
            .or_else(|| block.get_setting("profile_medium_rssi"))
            .or_else(|| block.get_setting("medium_threshold"))
            .and_then(|v| v.as_i64())
        {
            filter.medium_rssi = v;
        }
        if let Some(v) = block.get_setting("rssi_bad").and_then(|v| v.as_i64()) {
            filter.rssi_bad = v;
        }
        if let Some(v) = block.get_setting("rssi_low").and_then(|v| v.as_i64()) {
            filter.rssi_low = v;
        }
        if let Some(v) = block.get_setting("rssi_medium").and_then(|v| v.as_i64()) {
            filter.rssi_medium = v;
        }
        if let Some(v) = block.get_setting("rssi_good").and_then(|v| v.as_i64()) {
            filter.rssi_good = v;
        }
        if let Some(v) = block
            .get_setting("triangulation")
            .or_else(|| block.get_setting("enable_triangulation"))
            .and_then(|v| {
                v.as_bool().or_else(|| {
                    v.as_str().map(|s| {
                        let trimmed = s.trim();
                        trimmed.eq_ignore_ascii_case("true")
                            || trimmed == "1"
                            || trimmed.eq_ignore_ascii_case("yes")
                    })
                })
            })
        {
            filter.enable_triangulation = v;
        }
        if let Some(v) = block
            .get_setting("triangulation_min_aps")
            .or_else(|| block.get_setting("min_aps"))
            .and_then(|v| v.as_i64())
        {
            filter.triangulation_min_aps = v.max(2) as usize;
        }
        filter
    }

    pub fn calculate_triangulated_latlong(
        &self,
        ap_macs: &[String],
        client_rssis: &[i64],
        primary_floor: Option<&str>,
        state: &StateStore,
    ) -> Option<(f64, f64, usize)> {
        if !self.enable_triangulation || ap_macs.len() < self.triangulation_min_aps {
            return None;
        }

        // Deduplicate AP MACs: if an AP reports multiple readings (e.g. dual-band radios),
        // retain its strongest RSSI so single physical APs don't falsely satisfy min_aps.
        let mut ap_rssi_map: HashMap<&str, i64> = HashMap::new();
        for (idx, ap) in ap_macs.iter().enumerate() {
            if ap.is_empty() {
                continue;
            }
            if let Some(&rssi) = client_rssis.get(idx) {
                if rssi >= 0 || rssi < -128 {
                    continue;
                }
                let entry = ap_rssi_map.entry(ap.as_str()).or_insert(rssi);
                if rssi > *entry {
                    *entry = rssi;
                }
            }
        }

        if ap_rssi_map.len() < self.triangulation_min_aps {
            return None;
        }

        struct ApPoint {
            lat: f64,
            lon: f64,
            weight: f64,
        }

        let mut points: Vec<ApPoint> = Vec::new();

        for (ap, rssi) in ap_rssi_map {
            let Some(record) = state.get_record_with_historical(WLC_PSQL_STORE, ap) else {
                continue;
            };

            // Ensure AP is on the same floor as the primary floor.
            // APs with missing or null floor_uuid are strictly excluded when primary_floor is set.
            if let Some(req_floor) = primary_floor {
                if !req_floor.is_empty() {
                    let ap_floor = record.get("floor_uuid").and_then(|v| v.as_str()).unwrap_or("");
                    if ap_floor != req_floor {
                        continue;
                    }
                }
            }

            let lat_opt = record
                .get("latitude")
                .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .or_else(|| {
                    record
                        .get("client_latlong")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.split_once(','))
                        .and_then(|(l, _)| l.trim().parse::<f64>().ok())
                });

            let lon_opt = record
                .get("longitude")
                .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .or_else(|| {
                    record
                        .get("client_latlong")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.split_once(','))
                        .and_then(|(_, r)| r.trim().parse::<f64>().ok())
                });

            if let (Some(lat), Some(lon)) = (lat_opt, lon_opt) {
                if !lat.is_finite() || !lon.is_finite() {
                    continue;
                }
                // Ignore non-negative or out-of-range RSSI values (0 is a common sentinel for 'not heard'/invalid)
                if rssi >= 0 || rssi < -128 {
                    continue;
                }
                let weight = 10.0_f64.powf(rssi as f64 / 20.0);
                if weight.is_finite() && weight > 0.0 {
                    points.push(ApPoint { lat, lon, weight });
                }
            }
        }

        if points.len() < self.triangulation_min_aps {
            return None;
        }

        let mut sum_lat_w = 0.0;
        let mut sum_lon_w = 0.0;
        let mut sum_w = 0.0;

        for p in &points {
            sum_lat_w += p.lat * p.weight;
            sum_lon_w += p.lon * p.weight;
            sum_w += p.weight;
        }

        if !sum_w.is_finite() || sum_w <= 0.0 || !sum_lat_w.is_finite() || !sum_lon_w.is_finite() {
            return None;
        }

        let res_lat = sum_lat_w / sum_w;
        let res_lon = sum_lon_w / sum_w;

        if !res_lat.is_finite() || !res_lon.is_finite() {
            return None;
        }

        Some((res_lat, res_lon, points.len()))
    }

    pub fn classify_rssi(&self, rssi: i64) -> &'static str {
        if rssi <= self.rssi_bad {
            "bad"
        } else if rssi <= self.rssi_low {
            "low"
        } else if rssi <= self.rssi_medium {
            "medium"
        } else if rssi <= self.rssi_good {
            "good"
        } else {
            "excellent"
        }
    }

    pub fn classify_client_profile(&self, rssi: i64) -> &'static str {
        if rssi == 0 {
            "hard"
        } else if rssi <= self.soft_rssi {
            "soft"
        } else if rssi <= self.medium_rssi {
            "medium"
        } else {
            "hard"
        }
    }
}

impl Filter for NmspFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let Some(raw_mac) = event.get_str("client_mac").filter(|s| !s.trim().is_empty()) else {
            return Ok(vec![]);
        };
        let client_mac = normalize_mac(&raw_mac);
        event.set("client_mac", client_mac.clone());

        let mut ns = event.get_str("namespace_uuid").unwrap_or_default();
        let msg_type = event
            .get_str("type")
            .or_else(|| event.get_str("nmsp_type"))
            .unwrap_or_default();

        if msg_type == "measure" {
            let mut ap_macs: Vec<String> = Vec::new();
            if let Some(arr) = event.get("ap_mac").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        ap_macs.push(normalize_mac(s));
                    } else {
                        ap_macs.push(String::new());
                    }
                }
            } else if let Some(s) = event.get_str("ap_mac").or_else(|| event.get_str("wireless_station")) {
                ap_macs.push(normalize_mac(&s));
            }

            let mut client_rssis: Vec<i64> = Vec::new();
            if let Some(arr) = event.get("rssi").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(val) = v
                        .as_i64()
                        .or_else(|| v.as_f64().map(|f| f as i64))
                        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
                    {
                        client_rssis.push(val);
                    }
                }
            } else if let Some(val) = event_i64(&event, "rssi") {
                client_rssis.push(val);
            }

            let mut info_cache = None;
            let mut store_key = format!("{}{}", client_mac, ns);

            // If incoming event already has namespace_uuid, look it up directly
            if !ns.is_empty() {
                info_cache = state.get_record_with_historical(NMSP_STORE_INFO, &store_key);
            }

            // If namespace_uuid is missing or lookup returned None, discover namespace
            // by checking candidate APs in WLC_PSQL_STORE for an active NMSP_STORE_INFO record
            if info_cache.is_none() {
                let mut fallback_ns: Option<String> = None;
                for ap in &ap_macs {
                    if ap.is_empty() {
                        continue;
                    }
                    if let Some(wlc_rec) = state.get_record_with_historical(WLC_PSQL_STORE, ap) {
                        if let Some(wlc_ns) = wlc_rec.get("namespace_uuid").and_then(|v| v.as_str()) {
                            if !wlc_ns.is_empty() {
                                if fallback_ns.is_none() {
                                    fallback_ns = Some(wlc_ns.to_string());
                                }
                                let candidate_key = format!("{}{}", client_mac, wlc_ns);
                                if let Some(rec) = state.get_record_with_historical(NMSP_STORE_INFO, &candidate_key) {
                                    ns = wlc_ns.to_string();
                                    event.set("namespace_uuid", ns.clone());
                                    store_key = candidate_key;
                                    info_cache = Some(rec);
                                    break;
                                }
                            }
                        }
                    }
                }
                // If no AP had an associated record, fall back to the first candidate AP's tenant namespace
                if info_cache.is_none() && ns.is_empty() {
                    if let Some(f_ns) = fallback_ns {
                        ns = f_ns;
                        event.set("namespace_uuid", ns.clone());
                        store_key = format!("{}{}", client_mac, ns);
                    }
                }
            }

            let mut max_rssi_opt: Option<(usize, i64)> = None;
            for (idx, &val) in client_rssis.iter().enumerate() {
                if let Some(ap) = ap_macs.get(idx) {
                    if ap.is_empty() {
                        continue;
                    }
                }
                if max_rssi_opt.is_none_or(|(_, cur_max)| val > cur_max) {
                    max_rssi_opt = Some((idx, val));
                }
            }

            let current_time = if let Some(n) = event_i64(&event, "timestamp") {
                if n > 1_000_000_000_000 {
                    n / 1000
                } else {
                    n
                }
            } else {
                chrono::Utc::now().timestamp()
            };

            let mut to_cache = Map::new();
            let dot11_status: String;
            let chosen_rssi: i64;
            let chosen_ap: Option<String>;

            if let Some(existing_status) = event.get_str("dot11_status") {
                dot11_status = existing_status;
                chosen_rssi = max_rssi_opt.map(|(_, r)| r).unwrap_or(0);
                chosen_ap = max_rssi_opt.and_then(|(idx, _)| ap_macs.get(idx).filter(|s| !s.is_empty()).cloned());
            } else if let Some(ref info) = info_cache {
                // If last_seen is missing from legacy cache, fallback to current_time so it remains active
                let last_seen = info
                    .get("last_seen")
                    .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(current_time);

                if last_seen + 3600 > current_time {
                    let ap_associated = info
                        .get("wireless_station")
                        .and_then(|v| v.as_str())
                        .map(normalize_mac);

                    if let Some(assoc_ap) = ap_associated {
                        // Check if ap_macs includes the associated AP
                        if let Some(idx) = ap_macs.iter().position(|ap| ap == &assoc_ap) {
                            chosen_rssi = client_rssis.get(idx).copied().unwrap_or_else(|| {
                                max_rssi_opt.map(|(_, r)| r).unwrap_or(0)
                            });
                            chosen_ap = Some(assoc_ap);
                            dot11_status = "ASSOCIATED".to_string();

                            // Merge info cache into to_cache
                            for (k, v) in info {
                                to_cache.insert(k.clone(), v.clone());
                            }
                            if ns.is_empty() {
                                if let Some(info_ns) = info.get("namespace_uuid").and_then(|v| v.as_str()) {
                                    if !info_ns.is_empty() {
                                        ns = info_ns.to_string();
                                        event.set("namespace_uuid", ns.clone());
                                        store_key = format!("{}{}", client_mac, ns);
                                    }
                                }
                            }
                        } else {
                            // Associated AP did not report the client in this measurement: drop event
                            return Ok(vec![]);
                        }
                    } else {
                        dot11_status = "PROBING".to_string();
                        chosen_rssi = max_rssi_opt.map(|(_, r)| r).unwrap_or(0);
                        chosen_ap = max_rssi_opt.and_then(|(idx, _)| ap_macs.get(idx).filter(|s| !s.is_empty()).cloned());
                    }
                } else {
                    // Info expired: delete from local store and revert to PROBING
                    state.remove_record_local(NMSP_STORE_INFO, &store_key);
                    dot11_status = "PROBING".to_string();
                    chosen_rssi = max_rssi_opt.map(|(_, r)| r).unwrap_or(0);
                    chosen_ap = max_rssi_opt.and_then(|(idx, _)| ap_macs.get(idx).filter(|s| !s.is_empty()).cloned());
                }
            } else {
                dot11_status = "PROBING".to_string();
                chosen_rssi = max_rssi_opt.map(|(_, r)| r).unwrap_or(0);
                chosen_ap = max_rssi_opt.and_then(|(idx, _)| ap_macs.get(idx).filter(|s| !s.is_empty()).cloned());
            }

            // RSSI limit check: Logstash drops probing events with RSSI < -80
            if dot11_status != "ASSOCIATED" && chosen_rssi < -80 {
                return Ok(vec![]);
            }

            let label = self.classify_rssi(chosen_rssi);
            to_cache.insert("client_rssi".to_string(), json!(label));
            to_cache.insert("client_rssi_num".to_string(), json!(chosen_rssi));
            let profile = self.classify_client_profile(chosen_rssi);
            to_cache.insert("client_profile".to_string(), json!(profile));
            to_cache.insert("dot11_status".to_string(), json!(dot11_status));
            if let Some(ref ap) = chosen_ap {
                to_cache.insert("wireless_station".to_string(), json!(ap));
            }

            let mut triangulated = false;
            if self.enable_triangulation {
                let primary_floor = chosen_ap.as_ref().and_then(|ap| {
                    state.get_record_with_historical(WLC_PSQL_STORE, ap)
                        .and_then(|rec| rec.get("floor_uuid").and_then(|v| v.as_str()).map(|s| s.to_string()))
                });

                if let Some((tri_lat, tri_lon, ap_count)) = self.calculate_triangulated_latlong(
                    &ap_macs,
                    &client_rssis,
                    primary_floor.as_deref(),
                    state,
                ) {
                    let latlong_str = format!("{:.6},{:.6}", tri_lat, tri_lon);
                    to_cache.insert("client_latlong".to_string(), json!(latlong_str));
                    to_cache.insert("latitude".to_string(), json!(tri_lat));
                    to_cache.insert("longitude".to_string(), json!(tri_lon));
                    to_cache.insert("triangulation_aps".to_string(), json!(ap_count as i64));
                    triangulated = true;
                }
            }

            if !triangulated && !to_cache.contains_key("client_latlong") && !event.contains("client_latlong") {
                if let Some(ref ap) = chosen_ap {
                    if let Some(record) = state.get_record_with_historical(WLC_PSQL_STORE, ap) {
                        if let Some(ll) = record.get("client_latlong").and_then(|v| v.as_str()) {
                            to_cache.insert("client_latlong".to_string(), json!(ll));
                        } else {
                            let lat_opt = record
                                .get("latitude")
                                .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
                            let lon_opt = record
                                .get("longitude")
                                .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
                            if let (Some(lat), Some(lon)) = (lat_opt, lon_opt) {
                                to_cache.insert("client_latlong".to_string(), json!(format!("{:.6},{:.6}", lat, lon)));
                                to_cache.insert("latitude".to_string(), json!(lat));
                                to_cache.insert("longitude".to_string(), json!(lon));
                            }
                        }
                    }
                }
            }

            state.put_record(NMSP_STORE_MEASURE, &store_key, to_cache.clone())?;
            for (k, v) in to_cache {
                event.set(&k, v);
            }
            event.set("type", "nmsp");
            state.enrich(&mut event);
        } else if msg_type == "info" {
            let mut to_cache = Map::new();

            // Discover tenant namespace from wireless_station if info event lacks namespace_uuid
            if ns.is_empty() {
                if let Some(ws) = event.get_str("wireless_station") {
                    let ap = normalize_mac(&ws);
                    if let Some(wlc_rec) = state.get_record_with_historical(WLC_PSQL_STORE, &ap) {
                        if let Some(wlc_ns) = wlc_rec.get("namespace_uuid").and_then(|v| v.as_str()) {
                            if !wlc_ns.is_empty() {
                                ns = wlc_ns.to_string();
                                event.set("namespace_uuid", ns.clone());
                            }
                        }
                    }
                }
            }

            let store_key = format!("{}{}", client_mac, ns);
            for field in [
                "wireless_station",
                "wireless_channel",
                "wireless_id",
                "dot11_protocol",
                "dot11_reason",
                "wireless_mode",
                "mobility_status",
                "dot11_status",
                "last_seen",
                "namespace_uuid",
                "organization_uuid",
                "service_provider_uuid",
                "campus_uuid",
                "building_uuid",
                "floor_uuid",
                "zone_uuid",
            ] {
                if let Some(val) = event.get(field) {
                    if !val.is_null() {
                        to_cache.insert(field.to_string(), val.clone());
                    }
                }
            }

            if !ns.is_empty() && !to_cache.contains_key("namespace_uuid") {
                to_cache.insert("namespace_uuid".to_string(), json!(ns));
            }

            if let Some(ws) = to_cache.get("wireless_station").and_then(|v| v.as_str()) {
                to_cache.insert("wireless_station".to_string(), json!(normalize_mac(ws)));
            }

            let ts = if let Some(n) = event_i64(&event, "last_seen").or_else(|| event_i64(&event, "timestamp")) {
                if n > 1_000_000_000_000 {
                    n / 1000
                } else {
                    n
                }
            } else {
                chrono::Utc::now().timestamp()
            };

            to_cache.insert("last_seen".to_string(), json!(ts));
            to_cache.insert("dot11_status".to_string(), json!("ASSOCIATED"));

            state.put_record(NMSP_STORE_INFO, &store_key, to_cache.clone())?;
            for (k, v) in to_cache {
                event.set(&k, v);
            }
            event.set("type", "nmsp");
            event.set("dot11_status", "ASSOCIATED");
            event.set("client_profile", "hard");
            state.enrich(&mut event);
        } else {
            state.enrich(&mut event);
        }

        Ok(vec![event])
    }
}

#[derive(Debug, Clone, Default)]
pub struct LocationFilter;

impl LocationFilter {
    pub fn new() -> Self {
        Self
    }

    pub fn from_block(_block: &PluginBlock) -> Self {
        Self
    }
}

impl Filter for LocationFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let loc_obj_opt = event
            .get("[StreamingNotification][location]")
            .or_else(|| event.get("location"))
            .and_then(|v| v.as_object())
            .cloned();

        if let Some(loc_obj) = loc_obj_opt {
            let Some(raw_mac) = loc_obj
                .get("macAddress")
                .or_else(|| loc_obj.get("client_mac"))
                .and_then(|v| v.as_str())
            else {
                return Ok(vec![]);
            };
            let client_mac = normalize_mac(raw_mac);
            event.set("client_mac", client_mac.clone());

            let mut to_cache = Map::new();

            let hierarchy_opt = loc_obj
                .get("MapInfo")
                .or_else(|| loc_obj.get("mapInfo"))
                .and_then(|m| m.as_object())
                .and_then(|m| m.get("mapHierarchyString"))
                .or_else(|| loc_obj.get("mapHierarchyString"))
                .and_then(|v| v.as_str());

            if let Some(hierarchy) = hierarchy_opt {
                let parts: Vec<&str> = hierarchy.split('>').map(|s| s.trim()).collect();
                if let Some(campus) = parts.first().filter(|s| !s.is_empty()) {
                    to_cache.insert("campus".to_string(), json!(*campus));
                }
                if let Some(building) = parts.get(1).filter(|s| !s.is_empty()) {
                    to_cache.insert("building".to_string(), json!(*building));
                }
                if let Some(floor) = parts.get(2).filter(|s| !s.is_empty()) {
                    to_cache.insert("floor".to_string(), json!(*floor));
                }
                if let Some(zone) = parts.get(3).filter(|s| !s.is_empty()) {
                    to_cache.insert("zone".to_string(), json!(*zone));
                }
            }

            let geo_opt = loc_obj
                .get("GeoCoordinate")
                .or_else(|| loc_obj.get("geoCoordinate"))
                .and_then(|g| g.as_object());
            if let Some(geo) = geo_opt {
                let lat = geo.get("latitude").and_then(|v| v.as_f64());
                let lon = geo.get("longitude").and_then(|v| v.as_f64());
                if let (Some(lat_v), Some(lon_v)) = (lat, lon) {
                    to_cache.insert(
                        "client_latlong".to_string(),
                        json!(format!("{:.6},{:.6}", lat_v, lon_v)),
                    );
                }
            }

            if let Some(status) = loc_obj.get("dot11Status").and_then(|v| v.as_str()) {
                to_cache.insert("dot11_status".to_string(), json!(status));
            }
            if let Some(ap_mac) = loc_obj.get("apMacAddress").and_then(|v| v.as_str()) {
                to_cache.insert("wireless_station".to_string(), json!(normalize_mac(ap_mac)));
            }
            if let Some(ssid) = loc_obj.get("ssId").and_then(|v| v.as_str()) {
                to_cache.insert("wireless_id".to_string(), json!(ssid));
            }

            event.remove("StreamingNotification");
            event.set("type", "mse");
            event.set("client_profile", "hard");

            let ns = event.get_str("namespace_uuid").unwrap_or_default();
            let store_key = format!("{}{}", client_mac, ns);
            state.put_record(LOCATION_STORE, &store_key, to_cache.clone())?;

            for (k, v) in to_cache {
                event.set(&k, v);
            }

            state.enrich(&mut event);
            return Ok(vec![event]);
        }

        if let Some(raw_mac) = event.get_str("client_mac") {
            let client_mac = normalize_mac(&raw_mac);
            event.set("client_mac", client_mac.clone());

            let mut to_cache = Map::new();
            for field in [
                "campus",
                "building",
                "floor",
                "zone",
                "client_latlong",
                "dot11_status",
                "wireless_station",
                "wireless_id",
            ] {
                if let Some(v) = event.get(field) {
                    if !v.is_null() {
                        to_cache.insert(field.to_string(), v.clone());
                    }
                }
            }
            let ns = event.get_str("namespace_uuid").unwrap_or_default();
            let store_key = format!("{}{}", client_mac, ns);
            if !to_cache.is_empty() {
                state.put_record(LOCATION_STORE, &store_key, to_cache)?;
            }
            if !event.contains("type") {
                event.set("type", "mse");
            }
            if !event.contains("client_profile") {
                event.set("client_profile", "hard");
            }
            state.enrich(&mut event);
        }

        Ok(vec![event])
    }
}

#[derive(Debug, Clone)]
pub struct ApstateFilter {
    pub counter_store_counter: bool,
}

impl Default for ApstateFilter {
    fn default() -> Self {
        Self {
            counter_store_counter: true,
        }
    }
}

impl ApstateFilter {
    pub fn new(counter_store_counter: bool) -> Self {
        Self {
            counter_store_counter,
        }
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        let counter_store_counter = block
            .get_setting("counter_store_counter")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        Self {
            counter_store_counter,
        }
    }
}

impl Filter for ApstateFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        state.enrich(&mut event);
        if self.counter_store_counter {
            state.increment_counter(COUNTER_STORE, "rb_state", 1)?;
            if let Some(ns) = event.get_str("namespace_uuid").filter(|s| !s.is_empty()) {
                state.increment_counter(COUNTER_STORE, &format!("rb_state_{}", ns), 1)?;
            }
        }
        Ok(vec![event])
    }
}

const MINUTE: i64 = 60;
const DEFAULT_CONSOLIDATED_TIME: i64 = 180;
const DEFAULT_EXPIRED_TIME: i64 = 1200;
const DEFAULT_MAX_DWELL_TIME: i64 = 1440;
const DEFAULT_EXPIRED_REPETITIONS_TIME: i64 = 10080;

fn same_minute(time1: i64, time2: i64) -> bool {
    (time1 - (time1 % MINUTE)) == (time2 - (time2 % MINUTE))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationState {
    pub t_global: i64,
    pub t_last_seen: i64,
    pub t_swap_loc: i64,
    pub t_transition: i64,
    pub dwell_time: i64,
    pub old_loc: String,
    pub new_loc: String,
    pub consolidated: String,
    pub entrance: String,
    pub uuid: i64,
    pub uuid_prefix: String,
    #[serde(default)]
    pub repeat_locations: HashMap<String, i64>,
    #[serde(default)]
    pub lat_long: Option<String>,
}

impl LocationState {
    pub fn new_params(
        t_global: i64,
        t_last_seen: i64,
        t_transition: i64,
        old_loc: String,
        new_loc: String,
        consolidated: String,
        entrance: String,
        lat_long: Option<String>,
        uuid_prefix: String,
    ) -> Self {
        Self {
            t_global: t_global - (t_global % MINUTE),
            t_last_seen: t_last_seen - (t_last_seen % MINUTE),
            t_swap_loc: t_last_seen,
            t_transition: t_transition - (t_transition % MINUTE),
            dwell_time: 1,
            old_loc,
            new_loc,
            consolidated,
            entrance,
            uuid: 0,
            uuid_prefix,
            repeat_locations: HashMap::new(),
            lat_long,
        }
    }

    fn location_time_expired(&self, new_location: &LocationState, expired_time: i64) -> bool {
        new_location.t_last_seen - self.t_last_seen >= expired_time
    }

    fn new_location_change(&self, new_location: &LocationState) -> bool {
        self.new_loc != new_location.new_loc
    }

    fn time_to_consolidate(&self, new_location: &LocationState, consolidated_time: i64) -> bool {
        new_location.t_last_seen - self.t_last_seen >= consolidated_time
    }

    fn move_to_outside_events(
        &self,
        new_location_type: &str,
        old_location_repetitions: i64,
        popularity: f64,
        max_dwell_time: i64,
    ) -> Vec<Event> {
        let mut e = Event::new();
        e.set("timestamp", self.t_last_seen - MINUTE);
        e.set("old", self.new_loc.clone());
        e.set("new", "outside");
        e.set("dwell_time", self.dwell_time);
        e.set(
            "static",
            if self.dwell_time > max_dwell_time { 1_i64 } else { 0_i64 },
        );
        e.set("transition", 1_i64);
        e.set("repetitions", old_location_repetitions);
        e.set("popularity", popularity);
        e.set("session", format!("{}-{}", self.uuid_prefix, self.uuid));
        e.set(&format!("{}_uuid", new_location_type), self.new_loc.clone());
        e.set("type", new_location_type.to_string());
        vec![e]
    }

    fn consolidated_location_events(
        &mut self,
        new_location: &LocationState,
        new_location_type: &str,
        new_location_repetitions: i64,
        popularity: f64,
        max_dwell_time: i64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        let mut t = self.t_last_seen + MINUTE;
        while t <= new_location.t_last_seen {
            let mut e = Event::new();
            e.set("timestamp", t);
            e.set("old", new_location.new_loc.clone());
            e.set("new", new_location.new_loc.clone());
            e.set("transition", 0_i64);
            e.set("repetitions", new_location_repetitions);
            e.set("popularity", popularity);
            e.set("dwell_time", self.dwell_time);
            e.set(
                "static",
                if self.dwell_time > max_dwell_time { 1_i64 } else { 0_i64 },
            );
            e.set("session", format!("{}-{}", self.uuid_prefix, self.uuid));
            e.set(&format!("{}_uuid", new_location_type), new_location.new_loc.clone());
            e.set("type", new_location_type.to_string());
            if let Some(ll) = &new_location.lat_long {
                e.set("client_latlong", ll.clone());
            }
            events.push(e);
            self.dwell_time += 1;
            t += MINUTE;
        }
        events
    }

    fn from_last_session_events(
        &mut self,
        new_location: &LocationState,
        new_location_type: &str,
        old_location_repetitions: i64,
        popularity: f64,
        max_dwell_time: i64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        let mut t = self.t_global + MINUTE;
        while t <= (self.t_transition - MINUTE) {
            let mut e = Event::new();
            e.set("timestamp", t);
            e.set("old", self.consolidated.clone());
            e.set("new", self.consolidated.clone());
            e.set("session", format!("{}-{}", self.uuid_prefix, self.uuid));
            e.set("dwell_time", self.dwell_time);
            e.set(
                "static",
                if self.dwell_time > max_dwell_time { 1_i64 } else { 0_i64 },
            );
            e.set(&format!("{}_uuid", new_location_type), self.consolidated.clone());
            e.set("transition", 0_i64);
            e.set("repetitions", old_location_repetitions);
            e.set("popularity", popularity);
            e.set("type", new_location_type.to_string());
            if let Some(ll) = &new_location.lat_long {
                e.set("client_latlong", ll.clone());
            }
            events.push(e);
            self.dwell_time += 1;
            t += MINUTE;
        }
        events
    }

    fn transition_to_new_location_events(
        &mut self,
        new_location: &LocationState,
        new_location_type: &str,
        popularity: f64,
        max_dwell_time: i64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        let mut t = self.t_transition;
        while t <= self.t_last_seen {
            let mut e = Event::new();
            e.set("timestamp", t);
            e.set("old", self.consolidated.clone());
            e.set("new", new_location.new_loc.clone());
            e.set("session", format!("{}-{}", self.uuid_prefix, self.uuid));
            e.set(&format!("{}_uuid", new_location_type), new_location.new_loc.clone());
            e.set("dwell_time", self.dwell_time);
            e.set(
                "static",
                if self.dwell_time > max_dwell_time { 1_i64 } else { 0_i64 },
            );
            e.set("transition", 1_i64);
            e.set("repetitions", 0_i64);
            e.set("popularity", popularity);
            e.set("type", new_location_type.to_string());
            if let Some(ll) = &new_location.lat_long {
                e.set("client_latlong", ll.clone());
            }
            events.push(e);
            self.dwell_time += 1;
            t += MINUTE;
        }
        events
    }

    fn transition_from_outside_events(
        &self,
        new_location: &LocationState,
        new_location_type: &str,
        popularity: f64,
        max_dwell_time: i64,
    ) -> Vec<Event> {
        let mut e = Event::new();
        e.set("timestamp", self.t_global);
        e.set("old", self.consolidated.clone());
        e.set("new", self.entrance.clone());
        e.set("session", format!("{}-{}", self.uuid_prefix, self.uuid));
        e.set(&format!("{}_uuid", new_location_type), self.entrance.clone());
        e.set("transition", 1_i64);
        e.set("repetitions", 0_i64);
        e.set("popularity", popularity);
        e.set("dwell_time", 1_i64);
        e.set("static", if 1 > max_dwell_time { 1_i64 } else { 0_i64 });
        e.set("type", new_location_type.to_string());
        if let Some(ll) = &new_location.lat_long {
            e.set("client_latlong", ll.clone());
        }
        vec![e]
    }

    fn new_location_static_events(
        &mut self,
        new_location: &LocationState,
        new_location_type: &str,
        new_location_repetitions: i64,
        popularity: f64,
        max_dwell_time: i64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        let mut t = self.t_last_seen + MINUTE;
        while t <= new_location.t_last_seen {
            let mut e = Event::new();
            e.set("timestamp", t);
            e.set("old", new_location.new_loc.clone());
            e.set("new", new_location.new_loc.clone());
            e.set("session", format!("{}-{}", self.uuid_prefix, self.uuid));
            e.set(&format!("{}_uuid", new_location_type), new_location.new_loc.clone());
            e.set("dwell_time", self.dwell_time);
            e.set(
                "static",
                if self.dwell_time > max_dwell_time { 1_i64 } else { 0_i64 },
            );
            e.set("transition", 0_i64);
            e.set("repetitions", new_location_repetitions);
            e.set("popularity", popularity);
            e.set("type", new_location_type.to_string());
            if let Some(ll) = &new_location.lat_long {
                e.set("client_latlong", ll.clone());
            }
            events.push(e);
            self.dwell_time += 1;
            t += MINUTE;
        }
        events
    }

    pub fn update_location(
        &mut self,
        new_location: &LocationState,
        new_location_type: &str,
        consolidated_time: i64,
        expired_time: i64,
        max_dwell_time: i64,
        expired_repetitions_time: i64,
    ) -> Vec<Event> {
        let mut events = Vec::new();

        let mut new_location_repetitions = self
            .repeat_locations
            .get(&new_location.new_loc)
            .copied()
            .unwrap_or(0);
        let mut old_location_repetitions = self
            .repeat_locations
            .get(&self.new_loc)
            .copied()
            .unwrap_or(0);

        if (new_location.t_last_seen - self.t_last_seen) > expired_repetitions_time {
            new_location_repetitions = 0;
            old_location_repetitions = 0;
        }

        let mut popularity = (((new_location_repetitions as f64 / (self.uuid as f64 + 1.0) * 100.0) as i64 as f64 / 100.0) * 10.0).round() / 10.0;

        if self.location_time_expired(new_location, expired_time) {
            self.t_global = new_location.t_global;
            self.t_last_seen = new_location.t_last_seen;

            events.extend(self.move_to_outside_events(
                new_location_type,
                old_location_repetitions,
                popularity,
                max_dwell_time,
            ));

            self.t_transition = new_location.t_transition;
            self.old_loc = new_location.old_loc.clone();
            self.new_loc = new_location.new_loc.clone();
            self.consolidated = new_location.consolidated.clone();
            self.entrance = new_location.entrance.clone();
            self.dwell_time = new_location.dwell_time;
            self.lat_long = new_location.lat_long.clone();
            self.uuid += 1;
        }

        if self.new_location_change(new_location) {
            self.t_last_seen = new_location.t_last_seen;
            self.t_swap_loc = new_location.t_last_seen;
            self.old_loc = self.new_loc.clone();
            self.new_loc = new_location.new_loc.clone();

            if self.old_loc == self.consolidated {
                self.t_transition = new_location.t_last_seen;
            }
            return events;
        }

        if self.consolidated == new_location.new_loc {
            if !same_minute(self.t_last_seen, new_location.t_last_seen) {
                events.extend(self.consolidated_location_events(
                    new_location,
                    new_location_type,
                    new_location_repetitions,
                    popularity,
                    max_dwell_time,
                ));
            }
            self.t_last_seen = new_location.t_last_seen;
            return events;
        }

        if !self.time_to_consolidate(new_location, consolidated_time) {
            return events;
        }

        if self.consolidated == "outside" {
            events.extend(self.transition_from_outside_events(
                new_location,
                new_location_type,
                popularity,
                max_dwell_time,
            ));
            self.consolidated = self.entrance.clone();
            self.t_transition += MINUTE;
        } else {
            if (self.t_global + MINUTE) <= (self.t_transition - MINUTE) {
                events.extend(self.from_last_session_events(
                    new_location,
                    new_location_type,
                    old_location_repetitions,
                    popularity,
                    max_dwell_time,
                ));
            }
            self.uuid += 1;
            popularity = (((new_location_repetitions as f64 / (self.uuid as f64 + 1.0) * 100.0) as i64 as f64 / 100.0) * 10.0).round() / 10.0;
        }

        if same_minute(self.t_transition, self.t_global) {
            self.t_transition += MINUTE;
            self.t_last_seen += MINUTE;
        }

        self.dwell_time = 1;
        if self.t_transition <= self.t_last_seen {
            events.extend(self.transition_to_new_location_events(
                new_location,
                new_location_type,
                popularity,
                max_dwell_time,
            ));
        }

        self.dwell_time = 1;
        if (self.t_last_seen + MINUTE) <= new_location.t_last_seen {
            events.extend(self.new_location_static_events(
                new_location,
                new_location_type,
                new_location_repetitions,
                popularity,
                max_dwell_time,
            ));
        }

        new_location_repetitions += 1;
        self.repeat_locations
            .insert(new_location.new_loc.clone(), new_location_repetitions);
        self.t_global = new_location.t_last_seen;
        self.t_last_seen = new_location.t_last_seen;
        self.t_transition = new_location.t_transition;
        self.old_loc = new_location.new_loc.clone();
        self.new_loc = new_location.new_loc.clone();
        self.consolidated = new_location.new_loc.clone();
        self.lat_long = new_location.lat_long.clone();

        events
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientLocation {
    pub t_global_last_seen: i64,
    #[serde(default)]
    pub wireless_station: Option<String>,
    #[serde(default)]
    pub campus: Option<LocationState>,
    #[serde(default)]
    pub building: Option<LocationState>,
    #[serde(default)]
    pub floor: Option<LocationState>,
    #[serde(default)]
    pub zone: Option<LocationState>,
}

impl ClientLocation {
    pub fn from_event(event: &Event, uuid_prefix: &str, timestamp: i64) -> Self {
        let lat_long = event.get_str("client_latlong");
        let ws = event.get_str("wireless_station").map(|s| normalize_mac(&s));

        let campus = event
            .get_str("campus_uuid")
            .or_else(|| event.get_str("campus"))
            .filter(|s| !s.is_empty())
            .map(|val| {
                LocationState::new_params(
                    timestamp,
                    timestamp,
                    timestamp,
                    "outside".to_string(),
                    val.clone(),
                    "outside".to_string(),
                    val,
                    lat_long.clone(),
                    uuid_prefix.to_string(),
                )
            });

        let building = event
            .get_str("building_uuid")
            .or_else(|| event.get_str("building"))
            .filter(|s| !s.is_empty())
            .map(|val| {
                LocationState::new_params(
                    timestamp,
                    timestamp,
                    timestamp,
                    "outside".to_string(),
                    val.clone(),
                    "outside".to_string(),
                    val,
                    lat_long.clone(),
                    uuid_prefix.to_string(),
                )
            });

        let floor = event
            .get_str("floor_uuid")
            .or_else(|| event.get_str("floor"))
            .filter(|s| !s.is_empty())
            .map(|val| {
                LocationState::new_params(
                    timestamp,
                    timestamp,
                    timestamp,
                    "outside".to_string(),
                    val.clone(),
                    "outside".to_string(),
                    val,
                    lat_long.clone(),
                    uuid_prefix.to_string(),
                )
            });

        let zone = event
            .get_str("zone_uuid")
            .or_else(|| event.get_str("zone"))
            .filter(|s| !s.is_empty())
            .map(|val| {
                LocationState::new_params(
                    timestamp,
                    timestamp,
                    timestamp,
                    "outside".to_string(),
                    val.clone(),
                    "outside".to_string(),
                    val,
                    lat_long.clone(),
                    uuid_prefix.to_string(),
                )
            });

        Self {
            t_global_last_seen: timestamp,
            wireless_station: ws,
            campus,
            building,
            floor,
            zone,
        }
    }

    pub fn update_location(
        &mut self,
        new_loc: ClientLocation,
        consolidated_time: i64,
        expired_time: i64,
        max_dwell_time: i64,
        expired_repetitions_time: i64,
    ) -> Vec<Event> {
        self.t_global_last_seen = new_loc.t_global_last_seen;
        let mut events = Vec::new();

        let dims: [(&str, &mut Option<LocationState>, Option<LocationState>); 4] = [
            ("campus", &mut self.campus, new_loc.campus),
            ("building", &mut self.building, new_loc.building),
            ("floor", &mut self.floor, new_loc.floor),
            ("zone", &mut self.zone, new_loc.zone),
        ];

        for (dim_name, opt_state, opt_new_loc) in dims {
            if let Some(state) = opt_state {
                if let Some(new_state) = opt_new_loc {
                    events.extend(state.update_location(
                        &new_state,
                        dim_name,
                        consolidated_time,
                        expired_time,
                        max_dwell_time,
                        expired_repetitions_time,
                    ));
                }
            } else if let Some(new_state) = opt_new_loc {
                *opt_state = Some(new_state);
            }
        }

        if let Some(ws) = new_loc.wireless_station {
            self.wireless_station = Some(ws);
        }

        events
    }
}

#[derive(Debug, Clone)]
pub struct MobilityFilter {
    pub consolidated_time: i64,
    pub expired_time: i64,
    pub max_dwell_time: i64,
    pub expired_repetitions_time: i64,
    pub max_time_without_movement: i64,
    pub probe_ttl: i64,
    pub dwell_ttl: i64,
    pub dimensions_to_enrich: Vec<String>,
    pub mac_vendors: Arc<HashMap<String, String>>,
}

impl Default for MobilityFilter {
    fn default() -> Self {
        Self {
            consolidated_time: DEFAULT_CONSOLIDATED_TIME,
            expired_time: DEFAULT_EXPIRED_TIME,
            max_dwell_time: DEFAULT_MAX_DWELL_TIME,
            expired_repetitions_time: DEFAULT_EXPIRED_REPETITIONS_TIME,
            max_time_without_movement: 86400,
            probe_ttl: 7200,
            dwell_ttl: 86400,
            mac_vendors: Arc::new(MacVendorsEnrichFilter::default().vendors),
            dimensions_to_enrich: vec![
                "market_uuid".to_string(),
                "market".to_string(),
                "organization_uuid".to_string(),
                "organization".to_string(),
                "zone_uuid".to_string(),
                "zone".to_string(),
                "namespace_uuid".to_string(),
                "namespace".to_string(),
                "deployment_uuid".to_string(),
                "deployment".to_string(),
                "sensor_uuid".to_string(),
                "sensor_name".to_string(),
                "service_provider_uuid".to_string(),
                "service_provider".to_string(),
                "building_uuid".to_string(),
                "building".to_string(),
                "campus_uuid".to_string(),
                "campus".to_string(),
                "floor_uuid".to_string(),
                "floor".to_string(),
                "dot11_status".to_string(),
                "client_profile".to_string(),
                "client_rssi_num".to_string(),
                "client_mac_vendor".to_string(),
                "mac_vendor".to_string(),
                "triangulation_aps".to_string(),
            ],
        }
    }
}

impl MobilityFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        let mut filter = Self::default();
        if let Some(v) = block
            .get_setting("consolidated_time")
            .or_else(|| block.get_setting("consolidation_time"))
            .or_else(|| block.get_setting("consolidation_timer"))
            .and_then(|v| v.as_i64())
        {
            filter.consolidated_time = v;
        }
        if let Some(v) = block
            .get_setting("expired_time")
            .or_else(|| block.get_setting("expiration_time"))
            .or_else(|| block.get_setting("expiration_timer"))
            .and_then(|v| v.as_i64())
        {
            filter.expired_time = v;
        }
        if let Some(v) = block
            .get_setting("max_dwell_time")
            .or_else(|| block.get_setting("dwell_timer"))
            .and_then(|v| v.as_i64())
        {
            filter.max_dwell_time = v;
        }
        if let Some(v) = block
            .get_setting("expired_repetitions_time")
            .or_else(|| block.get_setting("repetitions_expiration_timer"))
            .and_then(|v| v.as_i64())
        {
            filter.expired_repetitions_time = v;
        }
        if let Some(v) = block
            .get_setting("max_time_without_movement")
            .or_else(|| block.get_setting("visitor_ttl"))
            .or_else(|| block.get_setting("client_ttl"))
            .or_else(|| block.get_setting("max_ttl"))
            .and_then(|v| v.as_i64())
        {
            filter.max_time_without_movement = v;
        }
        if let Some(v) = block
            .get_setting("probe_ttl")
            .or_else(|| block.get_setting("outside_ttl"))
            .or_else(|| block.get_setting("ephemeral_ttl"))
            .and_then(|v| v.as_i64())
        {
            filter.probe_ttl = v;
        }
        if let Some(v) = block
            .get_setting("dwell_ttl")
            .or_else(|| block.get_setting("dwell_store_ttl"))
            .and_then(|v| v.as_i64())
        {
            filter.dwell_ttl = v;
        }
        filter
    }
}

impl Filter for MobilityFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        state.enrich(&mut event);

        let Some(raw_mac) = event.get_str("client_mac") else {
            return Ok(vec![]);
        };
        let client_mac = normalize_mac(&raw_mac);
        event.set("client_mac", client_mac.clone());

        let ns = event.get_str("namespace_uuid").unwrap_or_default();
        let store_key = format!("{}{}", client_mac, ns);

        let timestamp = if let Some(n) = event_i64(&event, "timestamp") {
            if n > 1_000_000_000_000 {
                n / 1000
            } else {
                n
            }
        } else {
            chrono::Utc::now().timestamp()
        };

        let new_client = ClientLocation::from_event(&event, &store_key, timestamp);

        let (client, raw_events) = match state.get_record_with_historical(MOBILITY_STORE, &store_key) {
            Some(map) => match serde_json::from_value::<ClientLocation>(Value::Object(map)) {
                Ok(mut loaded) => {
                    let evs = loaded.update_location(
                        new_client,
                        self.consolidated_time,
                        self.expired_time,
                        self.max_dwell_time,
                        self.expired_repetitions_time,
                    );
                    (loaded, evs)
                }
                Err(_) => (new_client, Vec::new()),
            },
            None => (new_client, Vec::new()),
        };

        let is_consolidated = client.campus.as_ref().is_some_and(|l| l.consolidated != "outside")
            || client.building.as_ref().is_some_and(|l| l.consolidated != "outside")
            || client.floor.as_ref().is_some_and(|l| l.consolidated != "outside")
            || client.zone.as_ref().is_some_and(|l| l.consolidated != "outside");

        let visitor_ttl = if self.max_time_without_movement > 0 {
            self.max_time_without_movement as u64
        } else {
            86400
        };
        let probe_ttl = if self.probe_ttl > 0 {
            self.probe_ttl as u64
        } else {
            7200
        };

        let ttl_secs = if is_consolidated {
            visitor_ttl
        } else {
            probe_ttl
        };

        if let Ok(Value::Object(map)) = serde_json::to_value(&client) {
            state.put_record_with_ttl(MOBILITY_STORE, &store_key, map.clone(), Some(ttl_secs))?;
            if is_consolidated && self.dwell_ttl > 0 {
                let _ = state.put_record_with_ttl(DWELL_STORE, &store_key, map, Some(self.dwell_ttl as u64));
            }
        }

        let mut out_events = Vec::with_capacity(raw_events.len());
        for mut gen_event in raw_events {
            gen_event.set("client_mac", client_mac.clone());

            for dim in &self.dimensions_to_enrich {
                if !gen_event.contains(dim) {
                    if let Some(val) = event.get(dim) {
                        gen_event.set(dim, val.clone());
                    }
                }
            }

            if !gen_event.contains("client_profile") {
                gen_event.set("client_profile", "hard");
            }

            if !gen_event.contains("client_mac_vendor") {
                if let Some(val) = event.get("client_mac_vendor") {
                    gen_event.set("client_mac_vendor", val.clone());
                } else {
                    let cleaned: String = client_mac
                        .chars()
                        .filter(|c| c.is_ascii_hexdigit())
                        .take(6)
                        .collect::<String>()
                        .to_uppercase();
                    if cleaned.len() == 6 {
                        if let Some(v) = self.mac_vendors.get(&cleaned) {
                            gen_event.set("client_mac_vendor", v.clone());
                        }
                    }
                }
            }

            if let Some(v) = gen_event.get("client_mac_vendor") {
                if !gen_event.contains("mac_vendor") {
                    gen_event.set("mac_vendor", v.clone());
                }
            }

            if let Some(ws) = &client.wireless_station {
                if !gen_event.contains("wireless_station") {
                    gen_event.set("wireless_station", ws.clone());
                }
            }

            state.enrich(&mut gen_event);
            out_events.push(gen_event);
        }

        Ok(out_events)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DruidMetricsFilter;

impl DruidMetricsFilter {
    pub fn new() -> Self {
        Self
    }

    pub fn from_block(_block: &PluginBlock) -> Self {
        Self
    }
}

fn map_druid_metric(service: &str, metric: &str) -> Option<(&'static str, &'static str, bool)> {
    match service {
        "druid/broker" | "broker" => match metric {
            "query/time" => Some(("broker_query_time", "ms", false)),
            "query/bytes" => Some(("broker_query_bytes", "bytes", false)),
            "query/node/time" => Some(("broker_query_node_time", "ms", false)),
            "query/node/bytes" => Some(("broker_query_node_bytes", "bytes", false)),
            "query/node/ttfb" => Some(("broker_query_node_ttfb", "ms", false)),
            "query/intervalChunk/time" => Some(("broker_query_interval_chunk_time", "ms", false)),
            "query/count" | "query/Count" => Some(("broker_query_count", "count", false)),
            "query/success/count" => Some(("broker_query_success_count", "count", false)),
            "query/failed/count" => Some(("broker_query_failed_count", "count", false)),
            "query/interrupted/count" => Some(("broker_query_interrupted_count", "count", false)),
            "query/cache/total/numEntries" => {
                Some(("broker_cache_num_entries", "entries", false))
            }
            "query/cache/total/sizeBytes" => Some(("broker_cache_size_bytes", "bytes", false)),
            "query/cache/total/hits" => Some(("broker_cache_hits", "hits", false)),
            "query/cache/total/misses" => Some(("broker_cache_misses", "misses", false)),
            "query/cache/total/evictions" => {
                Some(("broker_cache_evictions", "evictions", false))
            }
            "query/cache/total/hitRate" => Some(("broker_cache_hit_rate", "rate", false)),
            "query/cache/total/averageBytes" => {
                Some(("broker_cache_average_bytes", "bytes", false))
            }
            "query/cache/total/timeouts" => Some(("broker_cache_timeouts", "timeouts", false)),
            "query/cache/total/errors" => Some(("broker_cache_errors", "errors", false)),
            _ => None,
        },
        "historical" | "druid/historical" => match metric {
            "query/time" => Some(("historical_query_time", "ms", false)),
            "query/cpu/time" => Some(("historical_query_cpu_time", "ms", true)),
            "query/segment/time" => Some(("historical_query_segment_time", "ms", false)),
            "query/wait/time" => Some(("historical_query_wait_time", "ms", false)),
            "query/segmentAndCache/time" => {
                Some(("historical_query_segment_and_cache_time", "ms", false))
            }
            "query/count" | "query/Count" => Some(("historical_query_count", "count", false)),
            "query/success/count" => Some(("historical_query_success_count", "count", false)),
            "query/failed/count" => Some(("historical_query_failed_count", "count", false)),
            "query/interrupted/count" => {
                Some(("historical_query_interrupted_count", "count", false))
            }
            "segment/max" => Some(("historical_segment_max", "bytes", false)),
            "segment/used" => Some(("historical_segment_used", "bytes", false)),
            "segment/usedPercent" => Some(("historical_segment_used_percent", "percent", false)),
            "segment/count" => Some(("historical_segment_count", "count", false)),
            "segment/scan/pending" => {
                Some(("historical_segment_scan_pending", "segments", false))
            }
            _ => None,
        },
        _ => None,
    }
}

const DRUID_REMOVE_FIELDS: [&str; 13] = [
    "version",
    "service",
    "feed",
    "metric",
    "host",
    "success",
    "hasFilters",
    "id",
    "remoteAddress",
    "duration",
    "interval",
    "context",
    "enableParallelMerge",
];

impl Filter for DruidMetricsFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let Some(service) = event.get_str("service") else {
            event.cancel();
            return Ok(vec![]);
        };
        let Some(metric) = event.get_str("metric") else {
            event.cancel();
            return Ok(vec![]);
        };

        let Some((monitor, unit, div_by_1000)) = map_druid_metric(&service, &metric) else {
            event.cancel();
            return Ok(vec![]);
        };

        if let Some(ts_str) = event.get("timestamp").and_then(|v| v.as_str()) {
            if let Ok(dt) = DateTime::parse_from_rfc3339(ts_str) {
                event.set("timestamp", dt.timestamp());
            }
        }

        if div_by_1000 {
            if let Some(val) = event_f64(&event, "value") {
                event.set("value", val / 1000.0);
            }
        }

        if let Some(host) = event.get_str("host") {
            let without_port = host.split(':').next().unwrap_or(&host);
            let sensor_name = without_port.split('.').next().unwrap_or(without_port);
            event.set("sensor_name", sensor_name.to_string());
        }

        event.set("monitor", monitor);
        event.set("unit", unit);
        event.set("type", "system");

        for field in DRUID_REMOVE_FIELDS {
            event.remove(field);
        }

        Ok(vec![event])
    }
}

#[derive(Debug)]
struct MemcachedConn {
    stream: std::io::BufReader<std::net::TcpStream>,
}

#[derive(Debug, Clone)]
pub struct SensorPolicy {
    pub id: String,
    pub name: String,
    pub thresholds: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelligenceFilter {
    pub policy_id: String,
    pub policy_name: String,
    pub category: String,
    pub indicator_fields: Vec<(String, String)>,
    pub memcached_servers: Vec<String>,
    pub memcached_addrs: Vec<std::net::SocketAddr>,
    pub sensors_policies: HashMap<String, SensorPolicy>,
    pub key_prefix: String,
    cache: std::sync::Arc<dashmap::DashMap<String, (Option<String>, std::time::Instant)>>,
    conn: std::sync::Arc<std::sync::Mutex<Option<MemcachedConn>>>,
    circuit_breaker_until: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Default for ThreatIntelligenceFilter {
    fn default() -> Self {
        Self {
            policy_id: "1".to_string(),
            policy_name: "default".to_string(),
            category: "reputation".to_string(),
            indicator_fields: vec![
                ("src".to_string(), "ip".to_string()),
                ("dst".to_string(), "ip".to_string()),
                ("host".to_string(), "domain".to_string()),
                ("url".to_string(), "url".to_string()),
                ("md5".to_string(), "hash".to_string()),
                ("sha256".to_string(), "hash".to_string()),
            ],
            memcached_servers: Vec::new(),
            memcached_addrs: Vec::new(),
            sensors_policies: HashMap::new(),
            key_prefix: "rbti".to_string(),
            cache: std::sync::Arc::new(dashmap::DashMap::new()),
            conn: std::sync::Arc::new(std::sync::Mutex::new(None)),
            circuit_breaker_until: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl ThreatIntelligenceFilter {
    pub fn new(
        policy_id: impl Into<String>,
        policy_name: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            policy_name: policy_name.into(),
            category: category.into(),
            ..Self::default()
        }
    }

    fn insert_cache(&self, key: &str, val: Option<String>) {
        if self.cache.len() > 100_000 {
            self.cache
                .retain(|_, (_, inst)| inst.elapsed() < std::time::Duration::from_secs(30));
        }
        self.cache
            .insert(key.to_string(), (val, std::time::Instant::now()));
    }

    pub fn query_memcached(&self, key: &str) -> Option<String> {
        if self.memcached_servers.is_empty() {
            return None;
        }

        // 1. Sanitize key: Memcached ASCII protocol forbids spaces, control characters, and length > 250
        if key.len() > 250
            || key
                .chars()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return None;
        }

        // 2. Check L1 cache
        if let Some(entry) = self.cache.get(key) {
            let (ref val, ref instant) = *entry;
            if instant.elapsed() < std::time::Duration::from_secs(30) {
                return val.clone();
            }
        }

        // 3. Check circuit breaker (skip if Memcached failed recently)
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_sec < self.circuit_breaker_until.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }

        let mut guard = match self.conn.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };

        // If no connection, attempt to connect
        if guard.is_none() {
            let mut addrs = self.memcached_addrs.clone();
            if addrs.is_empty() {
                use std::net::ToSocketAddrs;
                for server in &self.memcached_servers {
                    if let Ok(resolved) = server.to_socket_addrs() {
                        addrs.extend(resolved);
                    }
                }
            }

            let mut connected = None;
            for addr in &addrs {
                if let Ok(stream) =
                    std::net::TcpStream::connect_timeout(addr, std::time::Duration::from_millis(200))
                {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(200)));
                    let _ = stream.set_nodelay(true);
                    connected = Some(MemcachedConn {
                        stream: std::io::BufReader::new(stream),
                    });
                    break;
                }
            }

            if let Some(c) = connected {
                *guard = Some(c);
            } else {
                // Trip circuit breaker for 5 seconds to avoid cascading timeouts
                self.circuit_breaker_until
                    .store(now_sec + 5, std::sync::atomic::Ordering::Relaxed);
                self.insert_cache(key, None);
                return None;
            }
        }

        let Some(ref mut conn) = *guard else {
            return None;
        };

        use std::io::{BufRead, Read, Write};
        let cmd = format!("get {}\r\n", key);
        if conn.stream.get_mut().write_all(cmd.as_bytes()).is_err() {
            *guard = None;
            self.circuit_breaker_until
                .store(now_sec + 5, std::sync::atomic::Ordering::Relaxed);
            return None;
        }

        let mut line = String::new();
        if conn.stream.read_line(&mut line).is_err() {
            *guard = None;
            self.circuit_breaker_until
                .store(now_sec + 5, std::sync::atomic::Ordering::Relaxed);
            return None;
        }

        if line.starts_with("VALUE ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let bytes: usize = parts[3].parse().unwrap_or(0);
                if bytes > 65536 {
                    *guard = None;
                    return None;
                }
                let mut val_buf = vec![0u8; bytes];
                if conn.stream.read_exact(&mut val_buf).is_ok() {
                    let mut trailer = String::new();
                    let _ = conn.stream.read_line(&mut trailer); // \r\n
                    let _ = conn.stream.read_line(&mut trailer); // END\r\n

                    let val_str = String::from_utf8_lossy(&val_buf).trim().to_string();
                    self.insert_cache(key, Some(val_str.clone()));
                    return Some(val_str);
                }
            }
            *guard = None;
        } else if line.starts_with("END") {
            self.insert_cache(key, None);
            return None;
        } else {
            *guard = None;
        }

        None
    }

    pub fn lookup_key(&self, key: &str, state: &StateStore) -> Option<String> {
        if !self.memcached_servers.is_empty() {
            if let Some(val) = self.query_memcached(key) {
                return Some(val);
            }
        }
        if let Some(val) = state.get_kv(key).ok().flatten() {
            self.insert_cache(key, Some(val.clone()));
            return Some(val);
        }
        self.insert_cache(key, None);
        None
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        let mut filter = Self::default();
        if let Some(id) = block.get_str("policy_id") {
            filter.policy_id = id.to_string();
        }
        if let Some(name) = block.get_str("policy_name") {
            filter.policy_name = name.to_string();
        }
        if let Some(cat) = block.get_str("category") {
            filter.category = cat.to_string();
        }
        if let Some(prefix) = block.get_str("key_prefix") {
            filter.key_prefix = prefix.to_string();
        }
        if let Some(servers) = block.get_string_list("memcached_servers") {
            use std::net::ToSocketAddrs;
            for s in &servers {
                if let Ok(addrs) = s.to_socket_addrs() {
                    filter.memcached_addrs.extend(addrs);
                }
            }
            filter.memcached_servers = servers;
        }
        if let Some(sensors) = block.get_map("sensors_policies") {
            for (sensor_name, policy_cfg) in sensors {
                if let crate::config::ast::ConfigValue::Map(entries) = policy_cfg {
                    let mut id = "1".to_string();
                    let mut name = sensor_name.clone();
                    let mut thresholds = HashMap::new();
                    for (k, v) in entries {
                        if k == "id" {
                            if let Some(s) = v.as_str() {
                                id = s.to_string();
                            } else if let Some(n) = v.as_i64() {
                                id = n.to_string();
                            }
                        } else if k == "name" {
                            if let Some(s) = v.as_str() {
                                name = s.to_string();
                            }
                        } else if k.starts_with("threshold_") {
                            let ind_type = k.trim_start_matches("threshold_").to_string();
                            let val = match v {
                                crate::config::ast::ConfigValue::Number(n) => n,
                                crate::config::ast::ConfigValue::Integer(n) => n as f64,
                                crate::config::ast::ConfigValue::String(ref s) => {
                                    s.parse::<f64>().unwrap_or(0.0)
                                }
                                _ => 0.0,
                            };
                            thresholds.insert(ind_type, val);
                        }
                    }
                    filter.sensors_policies.insert(
                        sensor_name.clone(),
                        SensorPolicy {
                            id,
                            name,
                            thresholds,
                        },
                    );
                }
            }
        }
        if let Some(map) = block.get_map("indicators_mapping") {
            let mut custom_fields = Vec::new();
            for (field, val) in map {
                if let Some(ind_type) = val.as_str() {
                    custom_fields.push((field, ind_type.to_string()));
                }
            }
            if !custom_fields.is_empty() {
                filter.indicator_fields = custom_fields;
            }
        }
        filter
    }
}

impl Filter for ThreatIntelligenceFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let (policy_id, policy_name, sensor_policy) = if !self.sensors_policies.is_empty() {
            let Some(sname) = event.get_str("sensor_name") else {
                return Ok(vec![event]);
            };
            let Some(sp) = self.sensors_policies.get(sname.as_str()) else {
                return Ok(vec![event]);
            };
            (sp.id.clone(), sp.name.clone(), Some(sp))
        } else {
            let pid = event
                .get_str("ti_policy_id")
                .unwrap_or_else(|| self.policy_id.clone());
            let pname = event
                .get_str("ti_policy_name")
                .unwrap_or_else(|| self.policy_name.clone());
            (pid, pname, None)
        };

        let is_logstash_mode = !self.sensors_policies.is_empty();

        let mut clean_indicators = std::collections::HashSet::new();
        let mut malicious_candidates = Vec::new();

        for (field, ind_type) in &self.indicator_fields {
            let Some(val) = event.get_str(field).filter(|s| !s.is_empty()) else {
                continue;
            };

            let clean_key = format!("{}:{}:{}:c:{}", self.key_prefix, policy_id, ind_type, val);
            if self.lookup_key(&clean_key, state).is_some() {
                clean_indicators.insert(field.clone());
                continue;
            }

            let mal_key = format!("{}:{}:{}:m:{}", self.key_prefix, policy_id, ind_type, val);
            if let Some(weight_str) = self.lookup_key(&mal_key, state) {
                let weight = weight_str.parse::<f64>().unwrap_or(1.0);
                malicious_candidates.push((field.clone(), ind_type.clone(), val.to_string(), weight));
            }
        }

        let mut malicious_matched = Vec::new();
        let mut total_score = 0.0;
        let mut legacy_indicators = Vec::new();

        for (field, ind_type, val, weight) in malicious_candidates {
            if clean_indicators.contains(&field) {
                continue;
            }
            let score = if is_logstash_mode {
                weight * 100.0
            } else {
                weight
            };

            let threshold = sensor_policy
                .and_then(|p| p.thresholds.get(&ind_type))
                .copied()
                .unwrap_or(0.0);

            if score >= threshold {
                malicious_matched.push(field.clone());
                total_score += score;
                legacy_indicators.push(json!({
                    "field": field,
                    "type": ind_type,
                    "value": val,
                    "status": "malicious",
                    "score": score,
                }));
            }
        }

        event.set("ti_policy_id", policy_id);
        event.set("ti_policy_name", policy_name);

        if is_logstash_mode {
            let category = if !malicious_matched.is_empty() {
                "malicious"
            } else {
                "clean"
            };
            event.set("ti_category", category);

            if !malicious_matched.is_empty() {
                let count = malicious_matched.len() as f64;
                let avg_score = ((total_score / count) * 100.0).round() / 100.0;
                event.set("ti_average_score", avg_score);
                event.set("ti_indicators", malicious_matched.join(", "));
            }
        } else {
            let category = event
                .get_str("ti_category")
                .unwrap_or_else(|| self.category.clone());
            event.set("ti_category", category);

            if !legacy_indicators.is_empty() {
                let avg_score = total_score / (legacy_indicators.len() as f64);
                event.set("ti_average_score", avg_score);
                event.set("ti_indicators", Value::Array(legacy_indicators));
            }
        }

        Ok(vec![event])
    }
}

#[derive(Debug, Clone)]
pub struct IncidentEnrichmentFilter {
    pub incident_fields: Vec<String>,
    pub source: String,
    pub field_scores: HashMap<String, f64>,
    pub field_map: HashMap<String, String>,
    pub incidents_priority_filter: Option<String>,
    pub malware_score_threshold: f64,
    pub cache_expiration: u64,
}

impl Default for IncidentEnrichmentFilter {
    fn default() -> Self {
        let mut field_scores = HashMap::new();
        for (k, v) in [
            ("lan_ip", 100.0),
            ("src_ip", 100.0),
            ("src", 100.0),
            ("wan_ip", 100.0),
            ("dst", 100.0),
            ("dst_ip", 100.0),
            ("lan_port", 30.0),
            ("wan_port", 30.0),
            ("src_port", 30.0),
            ("dst_port", 30.0),
            ("sha256", 100.0),
        ] {
            field_scores.insert(k.to_string(), v);
        }

        let mut field_map = HashMap::new();
        for (k, v) in [
            ("lan_ip", "ip"),
            ("src_ip", "ip"),
            ("src", "ip"),
            ("wan_ip", "ip"),
            ("dst_ip", "ip"),
            ("dst", "ip"),
            ("lan_port", "port"),
            ("wan_port", "port"),
            ("src_port", "port"),
            ("dst_port", "port"),
            ("sha256", "hash"),
        ] {
            field_map.insert(k.to_string(), v.to_string());
        }

        Self {
            incident_fields: vec!["src".to_string(), "dst".to_string()],
            source: "vortex".to_string(),
            field_scores,
            field_map,
            incidents_priority_filter: None,
            malware_score_threshold: 50.0,
            cache_expiration: 600,
        }
    }
}

impl IncidentEnrichmentFilter {
    pub fn new(
        incident_fields: Vec<String>,
        source: impl Into<String>,
        field_scores: HashMap<String, f64>,
    ) -> Self {
        let mut def = Self::default();
        def.incident_fields = incident_fields;
        def.source = source.into();
        if !field_scores.is_empty() {
            def.field_scores = field_scores;
        }
        def
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        let mut filter = Self::default();
        if let Some(fields) = block.get_string_list("incident_fields") {
            filter.incident_fields = fields;
        }
        if let Some(source) = block.get_str("source") {
            filter.source = source.to_string();
        }
        if let Some(p) = block.get_str("incidents_priority_filter") {
            filter.incidents_priority_filter = Some(p.to_lowercase());
        }
        if let Some(t) = block.get_setting("malware_score_threshold").and_then(|v| v.as_f64()) {
            filter.malware_score_threshold = t;
        }
        if let Some(exp) = block.get_setting("cache_expiration").and_then(|v| v.as_i64()) {
            filter.cache_expiration = exp as u64;
        }
        if let Some(scores) = block.get_map("field_scores") {
            for (k, v) in scores {
                if let Some(score) = v.as_f64() {
                    filter.field_scores.insert(k, score);
                }
            }
        }
        if let Some(fmap) = block.get_map("field_map") {
            for (k, v) in fmap {
                if let Some(prefix) = v.as_str() {
                    filter.field_map.insert(k, prefix.to_string());
                }
            }
        }
        filter
    }

    fn get_score(&self, field: &str) -> f64 {
        self.field_scores.get(field).copied().unwrap_or(0.0)
    }

    fn field_prefix<'a>(&'a self, field: &'a str) -> &'a str {
        self.field_map
            .get(field)
            .map(|s| s.as_str())
            .unwrap_or(field)
    }

    fn get_cache_key_name(&self, prefix: &str, field: &str, value: &str) -> String {
        format!("{}:{}:{}", prefix, self.field_prefix(field), value)
    }

    fn get_key_prefix(&self, event: &Event) -> String {
        match event.get_str("namespace_uuid").filter(|s| !s.is_empty()) {
            Some(ns) => format!("rbincident:{}", ns),
            None => "rbincident".to_string(),
        }
    }

    fn get_domain_uuid(&self, event: &Event) -> Option<String> {
        event
            .get_str("organization_uuid")
            .or_else(|| event.get_str("namespace_uuid"))
            .or_else(|| event.get_str("service_provider_uuid"))
            .map(|s| s.to_string())
    }

    fn get_priority(&self, event: &Event) -> String {
        let raw = event
            .get_str("priority")
            .or_else(|| event.get_str("severity"))
            .or_else(|| event.get_str("syslogseverity_text"))
            .unwrap_or_else(|| "unknown".to_string())
            .to_lowercase();

        let valid = [
            "critical", "high", "medium", "low", "none", "unknown", "info", "emergency", "alert",
            "error", "warning", "notice", "debug",
        ];
        let mut priority = if valid.contains(&raw.as_str()) {
            raw
        } else {
            "unknown".to_string()
        };

        if self.source.eq_ignore_ascii_case("Malware") {
            let score = event
                .get("malware_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if score >= self.malware_score_threshold {
                priority = self.incidents_priority_filter.clone().unwrap_or_else(|| "critical".to_string());
            }
        }
        priority
    }

    fn get_name(&self, event: &Event) -> String {
        if self.source.eq_ignore_ascii_case("Malware") {
            let file_name = event.get_str("file_name").unwrap_or_else(|| "unknown file".to_string());
            format!("Malware detected in {}", file_name)
        } else if self.source.eq_ignore_ascii_case("Vault") {
            let sensor_name = event.get_str("sensor_name").unwrap_or_else(|| "unknown sensor".to_string());
            format!("Syslog incident from sensor {}", sensor_name)
        } else {
            event
                .get_str("msg")
                .or_else(|| event.get_str("message"))
                .unwrap_or_else(|| "Unknown incident".to_string())
        }
    }

    fn get_timestamp(&self, event: &Event) -> Value {
        if let Some(ts) = event.get("timestamp") {
            if let Some(num) = ts.as_i64() {
                let dt = if num > 1_000_000_000_000 {
                    chrono::DateTime::from_timestamp_millis(num)
                } else {
                    chrono::DateTime::from_timestamp(num, 0)
                };
                if let Some(dt) = dt {
                    return json!(dt.to_rfc3339());
                }
            } else if let Some(s) = ts.as_str() {
                return json!(s);
            }
        }
        if let Some(ts) = event.get("@timestamp") {
            if let Some(s) = ts.as_str() {
                return json!(s);
            } else if let Some(num) = ts.as_i64() {
                let dt = if num > 1_000_000_000_000 {
                    chrono::DateTime::from_timestamp_millis(num)
                } else {
                    chrono::DateTime::from_timestamp(num, 0)
                };
                if let Some(dt) = dt {
                    return json!(dt.to_rfc3339());
                }
            }
        }
        json!(chrono::Utc::now().to_rfc3339())
    }

    fn is_required_priority_or_above(&self, priority: &str, malware_score: f64) -> bool {
        let vault_priority_map: HashMap<&str, i32> = [
            ("debug", 1),
            ("info", 2),
            ("notice", 3),
            ("warning", 4),
            ("error", 5),
            ("critical", 6),
            ("alert", 7),
            ("emergency", 8),
        ]
        .into_iter()
        .collect();

        let intrusion_priority_map: HashMap<&str, i32> = [
            ("info", 1),
            ("unknown", 2),
            ("none", 3),
            ("low", 4),
            ("medium", 5),
            ("high", 6),
            ("critical", 7),
        ]
        .into_iter()
        .collect();

        if let Some(ref target_filter) = self.incidents_priority_filter {
            if self.source.eq_ignore_ascii_case("Intrusion") {
                if let (Some(&p_val), Some(&target_val)) = (
                    intrusion_priority_map.get(priority),
                    intrusion_priority_map.get(target_filter.as_str()),
                ) {
                    return p_val >= target_val;
                }
            } else if self.source.eq_ignore_ascii_case("Vault") {
                if let (Some(&p_val), Some(&target_val)) = (
                    vault_priority_map.get(priority),
                    vault_priority_map.get(target_filter.as_str()),
                ) {
                    return p_val >= target_val;
                }
            } else if self.source.eq_ignore_ascii_case("Malware") {
                return malware_score >= self.malware_score_threshold;
            }
            false
        } else if self.source.eq_ignore_ascii_case("Malware") {
            malware_score >= self.malware_score_threshold
        } else {
            true
        }
    }
}

impl Filter for IncidentEnrichmentFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let prefix = self.get_key_prefix(&event);
        let priority = self.get_priority(&event);
        let malware_score = event
            .get("malware_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let mut event_fields: HashMap<String, String> = HashMap::new();
        for field in &self.incident_fields {
            if let Some(val) = event.get_str(field).filter(|s| !s.is_empty()) {
                event_fields.insert(field.clone(), val.to_string());
            }
        }

        if event_fields.is_empty() {
            return Ok(vec![event]);
        }

        // 1. Calculate field scores by querying Redis for existing correlation keys
        let mut field_scores_map: Vec<(String, f64, Option<String>)> = Vec::new();

        for (field, val) in &event_fields {
            let score = self.get_score(field);
            let cache_key = self.get_cache_key_name(&prefix, field, val);
            let existing_uuid = state.get_raw_kv(&cache_key).unwrap_or(None);
            field_scores_map.push((field.clone(), score, existing_uuid));
        }

        field_scores_map.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Group existing scores by incident UUID to correlate against the same incident
        let mut score_per_uuid: HashMap<String, f64> = HashMap::new();
        for (_field, score, existing_uuid_opt) in &field_scores_map {
            if let Some(ref u) = existing_uuid_opt {
                *score_per_uuid.entry(u.clone()).or_insert(0.0) += *score;
            }
        }

        let best_existing = score_per_uuid
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut incident_uuid: Option<String> = None;

        if let Some((matched_uuid, _score)) = best_existing.filter(|&(_, s)| s >= 100.0) {
            incident_uuid = Some(matched_uuid.clone());
            for (field, _score, existing_uuid_opt) in &field_scores_map {
                let val = match event_fields.get(field) {
                    Some(v) => v,
                    None => continue,
                };
                let cache_key = self.get_cache_key_name(&prefix, field, val);
                if existing_uuid_opt.is_none() {
                    let _ = state.set_raw_kv(&cache_key, &matched_uuid, Some(self.cache_expiration));
                } else {
                    // Refresh TTL
                    let _ = state.set_raw_kv(&cache_key, &matched_uuid, Some(self.cache_expiration));
                }
            }
        } else if self.is_required_priority_or_above(&priority, malware_score) {
            // New incident creation
            let new_uuid = uuid::Uuid::new_v4().to_string();

            let mut incident_obj = json!({
                "uuid": new_uuid,
                "name": self.get_name(&event),
                "priority": priority,
                "source": self.source,
                "domain_uuid": self.get_domain_uuid(&event),
                "first_event_at": self.get_timestamp(&event)
            });

            if self.source == "Malware" {
                if let Some(h) = event.get_str("hash").or_else(|| event.get_str("sha256")) {
                    incident_obj["malware_hash"] = json!(h);
                } else {
                    incident_obj["malware_hash"] = json!("");
                }
            }

            // Save incident metadata key for mem2incident
            let incident_key = format!("{}:incident:{}", prefix, new_uuid);
            let incident_json = incident_obj.to_string();
            let _ = state.set_raw_kv(&incident_key, &incident_json, Some(self.cache_expiration));

            // Save field correlation keys
            let mut partner_uuid: Option<String> = None;
            for (field, _score, existing_uuid_opt) in &field_scores_map {
                let val = match event_fields.get(field) {
                    Some(v) => v,
                    None => continue,
                };
                let cache_key = self.get_cache_key_name(&prefix, field, val);
                if existing_uuid_opt.is_none() {
                    let _ = state.set_raw_kv(&cache_key, &new_uuid, Some(self.cache_expiration));
                } else if partner_uuid.is_none() {
                    partner_uuid = existing_uuid_opt.clone();
                }
            }

            // Save relation key if a partner was identified
            if let Some(partner) = partner_uuid {
                let relation_key = format!("rbincident:relation:{}", new_uuid);
                let _ = state.set_raw_kv(&relation_key, &partner, Some(self.cache_expiration));
            }

            incident_uuid = Some(new_uuid);
        }

        let event_total_score: f64 = field_scores_map.iter().map(|(_, s, _)| *s).sum();
        if let Some(u) = incident_uuid {
            event.set("incident_uuid", u);
            event.set("incident_source", self.source.clone());
            if event_total_score > 0.0 {
                event.set("incident_score", event_total_score);
            }
        }

        Ok(vec![event])
    }
}

#[derive(Debug, Clone, Default)]
pub struct IntrusionFilter;

impl IntrusionFilter {
    pub fn new() -> Self {
        Self
    }

    pub fn from_block(_block: &PluginBlock) -> Self {
        Self
    }
}

impl Filter for IntrusionFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        state.enrich(&mut event);
        Ok(vec![event])
    }
}

pub fn from_plugin_block(block: &PluginBlock) -> anyhow::Result<Option<Box<dyn Filter>>> {
    let filter: Box<dyn Filter> = match block.name.as_str() {
        "macscrambling" => Box::new(MacScramblingFilter::from_block(block)),
        "macvendorsenrich" => Box::new(MacVendorsEnrichFilter::from_block(block)),
        "netflowenrich" => Box::new(NetflowEnrichFilter::from_block(block)),
        "radius" => Box::new(RadiusFilter::from_block(block)),
        "nmsp" => Box::new(NmspFilter::from_block(block)),
        "location" => Box::new(LocationFilter::from_block(block)),
        "apstate" => Box::new(ApstateFilter::from_block(block)),
        "mobility" => Box::new(MobilityFilter::from_block(block)),
        "druid_metrics" => Box::new(DruidMetricsFilter::from_block(block)),
        "threat_intelligence" => Box::new(ThreatIntelligenceFilter::from_block(block)),
        "incident_enrichment" => Box::new(IncidentEnrichmentFilter::from_block(block)),
        "intrusion" => Box::new(IntrusionFilter::from_block(block)),
        "device_enrichment" | "deviceenrichment" => {
            Box::new(DeviceEnrichmentFilter::from_block(block))
        }
        _ => return Ok(None),
    };
    Ok(Some(filter))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceEnrichmentMode {
    Endpoint,
    Sensor,
    Auto,
}

impl Default for DeviceEnrichmentMode {
    fn default() -> Self {
        Self::Endpoint
    }
}

#[derive(Debug, Clone)]
pub struct DeviceEnrichmentFilter {
    pub mode: DeviceEnrichmentMode,
    pub fallback_to_sensor: bool,
}

impl Default for DeviceEnrichmentFilter {
    fn default() -> Self {
        Self {
            mode: DeviceEnrichmentMode::Endpoint,
            fallback_to_sensor: false,
        }
    }
}

impl DeviceEnrichmentFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        let mut filter = Self::default();
        if let Some(m) = block.get_str("mode") {
            filter.mode = match m.to_lowercase().as_str() {
                "sensor" | "probe" => DeviceEnrichmentMode::Sensor,
                "auto" => DeviceEnrichmentMode::Auto,
                _ => DeviceEnrichmentMode::Endpoint,
            };
        }
        if let Some(fb) = block
            .get_setting("fallback_to_sensor")
            .and_then(|v| v.as_bool())
            .or_else(|| {
                block
                    .get_str("fallback_to_sensor")
                    .and_then(|s| s.parse::<bool>().ok())
            })
        {
            filter.fallback_to_sensor = fb;
        }
        filter
    }
}

impl Filter for DeviceEnrichmentFilter {
    fn process(&self, mut event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let apply_enrichment = |ev: &mut Event, record: &Map<String, Value>| -> bool {
            let event_ns = ev.get_str("namespace_uuid").unwrap_or_default();
            let store_ns = record
                .get("namespace_uuid")
                .and_then(|v| v.as_str())
                .unwrap_or_default();

            // Strict Multi-Tenant Namespace Isolation:
            // - Events with a tenant namespace can ONLY be enriched by records from that exact namespace.
            // - Events without a namespace can ONLY be enriched by global records (no namespace).
            if event_ns != store_ns {
                return false;
            }
            let mut applied = false;
            for field in &["device_id", "device_name", "device_role"] {
                if !ev.contains(field) {
                    if let Some(val) = record.get(*field) {
                        if !val.is_null() {
                            ev.set(field, val.clone());
                            applied = true;
                        }
                    }
                }
            }
            applied
        };

        // If event has sensor_uuid, look up sensor record from SENSOR_PSQL_STORE
        let mut sensor_record_cached = None;
        if let Some(sensor_u) = event.get_str("sensor_uuid") {
            if !sensor_u.is_empty() {
                if let Some(sensor_rec) = state.get_record_with_historical(SENSOR_PSQL_STORE, &sensor_u) {
                    if event
                        .get_str("namespace_uuid")
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                    {
                        if let Some(ns) = sensor_rec.get("namespace_uuid").and_then(|v| v.as_str()) {
                            if !ns.is_empty() {
                                event.set("namespace_uuid", ns);
                            }
                        }
                    }
                    sensor_record_cached = Some(sensor_rec);
                }
            }
        }

        let sensor_device_id: Option<String> = sensor_record_cached
            .as_ref()
            .and_then(|rec| rec.get("device_id"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });

        let has_endpoint_data = [
            "lan_ip",
            "wan_ip",
            "src_ip",
            "dst_ip",
            "client_mac",
            "server_mac",
            "mac",
        ]
        .iter()
        .any(|f| event.get_str(f).map(|s| !s.trim().is_empty()).unwrap_or(false));

        let is_sensor_mode = match self.mode {
            DeviceEnrichmentMode::Sensor => true,
            DeviceEnrichmentMode::Endpoint => false,
            DeviceEnrichmentMode::Auto => !has_endpoint_data,
        };

        if !is_sensor_mode {
            // 1. Endpoint MAC match (highest precedence: hardware address is unique and authoritative under DHCP)
            for mac_field in &["client_mac", "mac", "server_mac"] {
                if let Some(mac) = event.get_str(mac_field) {
                    let norm = normalize_mac(&mac);
                    if !norm.is_empty() && norm != "00:00:00:00:00:00" {
                        let rec_opt = match event.get_str("namespace_uuid").filter(|ns| !ns.trim().is_empty()) {
                            Some(ns) => state.get_record_with_historical(
                                DEVICE_MAC_PSQL_STORE,
                                &format!("{}:{}", ns.trim(), norm),
                            ),
                            None => state.get_record_with_historical(DEVICE_MAC_PSQL_STORE, &norm),
                        };

                        if let Some(rec) = rec_opt {
                            // If this MAC is server_mac and resolves to the exporting sensor router device,
                            // skip it so transit gateway MAC does not misattribute passing endpoint flows.
                            if *mac_field == "server_mac" {
                                let rec_dev_id: Option<String> = rec.get("device_id").and_then(|v| match v {
                                    Value::String(s) => Some(s.clone()),
                                    Value::Number(n) => Some(n.to_string()),
                                    _ => None,
                                });
                                if let (Some(r_id), Some(ref s_id)) = (rec_dev_id, &sensor_device_id) {
                                    if &r_id == s_id {
                                        continue;
                                    }
                                }
                            }

                            if apply_enrichment(&mut event, &rec) {
                                return Ok(vec![event]);
                            }
                        }
                    }
                }
            }

            // 2. Endpoint IP match (fallback when MAC is absent or unmanaged)
            for ip_field in &["lan_ip", "src_ip", "wan_ip", "dst_ip"] {
                if let Some(ip) = event.get_str(ip_field) {
                    let clean_ip = ip.trim();
                    if !clean_ip.is_empty() {
                        let rec_opt = match event.get_str("namespace_uuid").filter(|ns| !ns.trim().is_empty()) {
                            Some(ns) => state.get_record_with_historical(
                                DEVICE_IP_PSQL_STORE,
                                &format!("{}:{}", ns.trim(), clean_ip),
                            ),
                            None => state.get_record_with_historical(DEVICE_IP_PSQL_STORE, clean_ip),
                        };

                        if let Some(rec) = rec_opt {
                            // If this IP is wan_ip or dst_ip and resolves to the exporting sensor router device,
                            // skip it so router WAN transit IP does not preempt endpoint resolution.
                            if *ip_field == "wan_ip" || *ip_field == "dst_ip" {
                                let rec_dev_id: Option<String> = rec.get("device_id").and_then(|v| match v {
                                    Value::String(s) => Some(s.clone()),
                                    Value::Number(n) => Some(n.to_string()),
                                    _ => None,
                                });
                                if let (Some(r_id), Some(ref s_id)) = (rec_dev_id, &sensor_device_id) {
                                    if &r_id == s_id {
                                        continue;
                                    }
                                }
                            }

                            if apply_enrichment(&mut event, &rec) {
                                return Ok(vec![event]);
                            }
                        }
                    }
                }
            }

            if !self.fallback_to_sensor {
                return Ok(vec![event]);
            }
        }

        // 3. Fallback to sensor or explicit Sensor mode
        if let Some(ref record) = sensor_record_cached {
            apply_enrichment(&mut event, record);
        } else if let Some(sensor_uuid) = event.get_str("sensor_uuid") {
            if !sensor_uuid.is_empty() {
                if let Some(record) = state.get_record_with_historical(SENSOR_PSQL_STORE, &sensor_uuid) {
                    apply_enrichment(&mut event, &record);
                }
            }
        }

        Ok(vec![event])
    }
}
