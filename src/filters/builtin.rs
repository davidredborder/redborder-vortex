use crate::config::ast::{ConfigValue, PluginBlock};
use crate::event::Event;
use crate::filters::Filter;
use crate::state::StateStore;
use ipnet::IpNet;
use regex::Regex;
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use dashmap::DashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ConvertType {
    Integer,
    Float,
    String,
    Boolean,
}

impl ConvertType {
    fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "integer" | "int" => Some(Self::Integer),
            "float" => Some(Self::Float),
            "string" => Some(Self::String),
            "boolean" | "bool" => Some(Self::Boolean),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MutateOp {
    Copy(Vec<(String, String)>),
    Rename(Vec<(String, String)>),
    Replace(Vec<(String, ConfigValue)>),
    AddField(Vec<(String, ConfigValue)>),
    RemoveField(Vec<String>),
    AddTag(Vec<String>),
    RemoveTag(Vec<String>),
    Convert(Vec<(String, ConvertType)>),
}

#[derive(Debug, Clone, Default)]
pub struct MutateFilter {
    pub ops: Vec<MutateOp>,
}

fn config_value_to_string_pairs(val: &ConfigValue) -> Vec<(String, String)> {
    match val {
        ConfigValue::Map(entries) => entries
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
        ConfigValue::Array(items) => {
            let mut pairs = Vec::new();
            for chunk in items.chunks(2) {
                if chunk.len() == 2 {
                    if let (Some(k), Some(v)) = (chunk[0].as_str(), chunk[1].as_str()) {
                        pairs.push((k.to_string(), v.to_string()));
                    }
                }
            }
            pairs
        }
        _ => Vec::new(),
    }
}

fn config_value_to_cfg_pairs(val: &ConfigValue) -> Vec<(String, ConfigValue)> {
    match val {
        ConfigValue::Map(entries) => entries.clone(),
        ConfigValue::Array(items) => {
            let mut pairs = Vec::new();
            for chunk in items.chunks(2) {
                if chunk.len() == 2 {
                    if let Some(k) = chunk[0].as_str() {
                        pairs.push((k.to_string(), chunk[1].clone()));
                    }
                }
            }
            pairs
        }
        _ => Vec::new(),
    }
}

fn config_value_to_string_list(val: &ConfigValue) -> Vec<String> {
    match val {
        ConfigValue::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        v => v.as_str().map(|s| vec![s.to_string()]).unwrap_or_default(),
    }
}

fn evaluate_template_or_scalar(event: &Event, val: &ConfigValue) -> Value {
    match val {
        ConfigValue::String(s) | ConfigValue::Identifier(s) => Value::String(event.interpolate(s)),
        other => other.to_json_value(),
    }
}

fn convert_value(val: &Value, target_type: &ConvertType) -> Option<Value> {
    match target_type {
        ConvertType::Integer => {
            let i = match val {
                Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))?,
                Value::String(s) => {
                    let trimmed = s.trim();
                    trimmed
                        .parse::<i64>()
                        .ok()
                        .or_else(|| trimmed.parse::<f64>().ok().map(|f| f as i64))?
                }
                Value::Bool(b) => {
                    if *b {
                        1
                    } else {
                        0
                    }
                }
                _ => return None,
            };
            Some(Value::Number(i.into()))
        }
        ConvertType::Float => {
            let f = match val {
                Value::Number(n) => n.as_f64()?,
                Value::String(s) => s.trim().parse::<f64>().ok()?,
                Value::Bool(b) => {
                    if *b {
                        1.0
                    } else {
                        0.0
                    }
                }
                _ => return None,
            };
            Number::from_f64(f).map(Value::Number)
        }
        ConvertType::String => {
            let s = match val {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => return None,
            };
            Some(Value::String(s))
        }
        ConvertType::Boolean => {
            let b = match val {
                Value::Bool(b) => *b,
                Value::Number(n) => n.as_i64().map(|i| i != 0).unwrap_or(false),
                Value::String(s) => match s.trim().to_lowercase().as_str() {
                    "true" | "1" | "yes" | "y" | "t" => true,
                    "false" | "0" | "no" | "n" | "f" => false,
                    _ => return None,
                },
                _ => return None,
            };
            Some(Value::Bool(b))
        }
    }
}

impl MutateFilter {
    pub fn from_config(block: &PluginBlock) -> anyhow::Result<Self> {
        let mut ops = Vec::new();
        for (key, val) in &block.settings {
            match key.as_str() {
                "copy" => ops.push(MutateOp::Copy(config_value_to_string_pairs(val))),
                "rename" => ops.push(MutateOp::Rename(config_value_to_string_pairs(val))),
                "replace" => ops.push(MutateOp::Replace(config_value_to_cfg_pairs(val))),
                "add_field" => ops.push(MutateOp::AddField(config_value_to_cfg_pairs(val))),
                "remove_field" => ops.push(MutateOp::RemoveField(config_value_to_string_list(val))),
                "add_tag" => ops.push(MutateOp::AddTag(config_value_to_string_list(val))),
                "remove_tag" => ops.push(MutateOp::RemoveTag(config_value_to_string_list(val))),
                "convert" => {
                    let raw_pairs = config_value_to_string_pairs(val);
                    let mut convs = Vec::with_capacity(raw_pairs.len());
                    for (field, type_str) in raw_pairs {
                        if let Some(ct) = ConvertType::from_str(&type_str) {
                            convs.push((field, ct));
                        }
                    }
                    ops.push(MutateOp::Convert(convs));
                }
                _ => {}
            }
        }
        Ok(Self { ops })
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        Self::from_config(block).unwrap_or_default()
    }
}

impl Filter for MutateFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        for op in &self.ops {
            match op {
                MutateOp::Copy(pairs) => {
                    for (src, dst) in pairs {
                        if let Some(val) = event.get(src).cloned() {
                            event.set(dst, val);
                        }
                    }
                }
                MutateOp::Rename(pairs) => {
                    for (old_f, new_f) in pairs {
                        if let Some(val) = event.remove(old_f) {
                            event.set(new_f, val);
                        }
                    }
                }
                MutateOp::Replace(pairs) | MutateOp::AddField(pairs) => {
                    for (field, template) in pairs {
                        let rendered = evaluate_template_or_scalar(&event, template);
                        event.set(field, rendered);
                    }
                }
                MutateOp::RemoveField(fields) => {
                    for field in fields {
                        event.remove(field);
                    }
                }
                MutateOp::AddTag(tags) => {
                    for t in tags {
                        let interpolated = event.interpolate(t);
                        event.tag(&interpolated);
                    }
                }
                MutateOp::RemoveTag(tags) => {
                    if let Some(Value::Array(arr)) = event.as_map_mut().get_mut("tags") {
                        arr.retain(|v| {
                            v.as_str()
                                .map(|s| !tags.iter().any(|t| t == s))
                                .unwrap_or(true)
                        });
                    }
                }
                MutateOp::Convert(convs) => {
                    for (field, target_type) in convs {
                        if let Some(existing) = event.get(field).cloned() {
                            if let Some(converted) = convert_value(&existing, target_type) {
                                event.set(field, converted);
                            }
                        }
                    }
                }
            }
        }
        Ok(vec![event])
    }
}

#[derive(Debug, Clone, Default)]
pub struct CidrFilter {
    pub addresses: Vec<String>,
    pub networks: Vec<IpNet>,
    pub add_field: Vec<(String, ConfigValue)>,
    pub add_tag: Vec<String>,
}

fn parse_ip_net(s: &str) -> Option<IpNet> {
    let trimmed = s.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Some(net);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(IpNet::from(ip));
    }
    None
}

impl CidrFilter {
    pub fn from_config(block: &PluginBlock) -> anyhow::Result<Self> {
        let mut addresses = Vec::new();
        let mut networks = Vec::new();
        let mut add_field = Vec::new();
        let mut add_tag = Vec::new();

        for (key, val) in &block.settings {
            match key.as_str() {
                "address" => {
                    addresses.extend(config_value_to_string_list(val));
                }
                "network" => {
                    for net_str in config_value_to_string_list(val) {
                        if let Some(net) = parse_ip_net(&net_str) {
                            networks.push(net);
                        }
                    }
                }
                "add_field" => {
                    add_field.extend(config_value_to_cfg_pairs(val));
                }
                "add_tag" => {
                    add_tag.extend(config_value_to_string_list(val));
                }
                _ => {}
            }
        }

        Ok(Self {
            addresses,
            networks,
            add_field,
            add_tag,
        })
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        Self::from_config(block).unwrap_or_default()
    }
}

impl Filter for CidrFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let mut matched = false;
        for addr_template in &self.addresses {
            let interpolated = event.interpolate(addr_template);
            if let Ok(ip) = interpolated.trim().parse::<IpAddr>() {
                if self.networks.iter().any(|net| net.contains(&ip)) {
                    matched = true;
                    break;
                }
            }
        }

        if matched {
            for (field, template) in &self.add_field {
                let rendered = evaluate_template_or_scalar(&event, template);
                event.set(field, rendered);
            }
            for tag in &self.add_tag {
                let rendered_tag = event.interpolate(tag);
                event.tag(&rendered_tag);
            }
        }

        Ok(vec![event])
    }
}

#[derive(Clone)]
pub struct GeoipFilter {
    pub source: String,
    pub default_database_type: String,
    pub target: String,
    pub fields: Vec<String>,
    pub database_path: Option<String>,
    pub reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl std::fmt::Debug for GeoipFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoipFilter")
            .field("source", &self.source)
            .field("default_database_type", &self.default_database_type)
            .field("target", &self.target)
            .field("fields", &self.fields)
            .field("database_path", &self.database_path)
            .field("has_reader", &self.reader.is_some())
            .finish()
    }
}

static MMDB_CACHE: OnceLock<DashMap<PathBuf, Arc<maxminddb::Reader<Vec<u8>>>>> = OnceLock::new();

fn get_mmdb_cache() -> &'static DashMap<PathBuf, Arc<maxminddb::Reader<Vec<u8>>>> {
    MMDB_CACHE.get_or_init(DashMap::new)
}

fn open_cached_mmdb(path: &Path) -> Option<Arc<maxminddb::Reader<Vec<u8>>>> {
    let cache = get_mmdb_cache();
    match cache.entry(path.to_path_buf()) {
        dashmap::mapref::entry::Entry::Occupied(occ) => Some(occ.get().clone()),
        dashmap::mapref::entry::Entry::Vacant(vac) => match maxminddb::Reader::open_readfile(path) {
            Ok(reader) => {
                let arc = Arc::new(reader);
                vac.insert(arc.clone());
                Some(arc)
            }
            Err(err) => {
                eprintln!("Failed to open MaxMind database at {:?}: {}", path, err);
                None
            }
        },
    }
}

const DEFAULT_CITY_DB_PATHS: &[&str] = &[
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/etc/logstash/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoIP2-City.mmdb",
    "/usr/share/GeoIP/GeoIP2-City.mmdb",
];

const DEFAULT_ASN_DB_PATHS: &[&str] = &[
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/etc/logstash/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoIP2-ASN.mmdb",
    "/usr/share/GeoIP/GeoIP2-ASN.mmdb",
];

fn find_mmdb_reader(
    explicit_db: Option<&str>,
    db_type: &str,
) -> (Option<String>, Option<Arc<maxminddb::Reader<Vec<u8>>>>) {
    if let Some(db_path) = explicit_db {
        let p = Path::new(db_path);
        if p.exists() {
            if let Some(reader) = open_cached_mmdb(p) {
                return (Some(db_path.to_string()), Some(reader));
            }
            eprintln!("WARNING: GeoIP database at {:?} exists but failed to read/parse", p);
        } else {
            eprintln!("WARNING: Configured GeoIP database at {:?} does not exist", p);
        }
        return (Some(db_path.to_string()), None);
    }

    let is_asn = db_type.eq_ignore_ascii_case("ASN");
    let env_var = if is_asn { "GEOIP_ASN_DB" } else { "GEOIP_CITY_DB" };
    if let Ok(env_path) = std::env::var(env_var) {
        let p = Path::new(&env_path);
        if p.exists() {
            if let Some(reader) = open_cached_mmdb(p) {
                return (Some(env_path), Some(reader));
            }
        }
    }
    if let Ok(generic_env) = std::env::var("GEOIP_DB") {
        let p = Path::new(&generic_env);
        if p.exists() {
            if let Some(reader) = open_cached_mmdb(p) {
                return (Some(generic_env), Some(reader));
            }
        }
    }

    let candidates = if is_asn {
        DEFAULT_ASN_DB_PATHS
    } else {
        DEFAULT_CITY_DB_PATHS
    };

    for path_str in candidates {
        let p = Path::new(path_str);
        if p.exists() {
            if let Some(reader) = open_cached_mmdb(p) {
                return (Some(path_str.to_string()), Some(reader));
            }
        }
    }

    (None, None)
}

impl Default for GeoipFilter {
    fn default() -> Self {
        Self {
            source: "ip".to_string(),
            default_database_type: "City".to_string(),
            target: "geoip".to_string(),
            fields: Vec::new(),
            database_path: None,
            reader: None,
        }
    }
}

fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64)
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0b1111_1110) == 18)
                || (v4.octets()[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public_ip(&IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

fn lookup_public_geoip(ip: &IpAddr) -> (&'static str, &'static str) {
    match ip.to_string().as_str() {
        "8.8.8.8" | "8.8.4.4" => ("US", "GOOGLE"),
        "1.1.1.1" | "1.0.0.1" => ("AU", "CLOUDFLARENET"),
        "93.184.216.34" => ("US", "EDGECAST"),
        "208.67.222.222" | "208.67.220.220" => ("US", "CISCO-UMBRELLA"),
        _ => ("US", "AS-PUBLIC"),
    }
}

impl GeoipFilter {
    pub fn wants_field(&self, name: &str, alt_name: &str) -> bool {
        if self.fields.is_empty() {
            return true;
        }
        self.fields.iter().any(|f| {
            f.eq_ignore_ascii_case(name) || f.eq_ignore_ascii_case(alt_name)
        })
    }

    pub fn from_config(block: &PluginBlock) -> anyhow::Result<Self> {
        let source = block.get_str("source").unwrap_or("ip").to_string();
        let default_database_type = block
            .get_str("default_database_type")
            .unwrap_or("City")
            .to_string();
        let target = block.get_str("target").unwrap_or("geoip").to_string();
        let fields = block.get_string_list("fields").unwrap_or_default();
        let explicit_database = block.get_str("database");

        let (database_path, reader) = find_mmdb_reader(explicit_database, &default_database_type);

        Ok(Self {
            source,
            default_database_type,
            target,
            fields,
            database_path,
            reader,
        })
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        Self::from_config(block).unwrap_or_default()
    }
}

impl Filter for GeoipFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let Some(ip_str) = event.get_str(&self.source) else {
            return Ok(vec![event]);
        };
        let Ok(ip) = ip_str.trim().parse::<IpAddr>() else {
            return Ok(vec![event]);
        };
        if is_non_public_ip(&ip) {
            return Ok(vec![event]);
        }

        let target_clean = self.target.trim_matches(|c| c == '[' || c == ']');

        if let Some(ref reader) = self.reader {
            if self.default_database_type.eq_ignore_ascii_case("ASN") {
                if let Ok(asn) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                    if self.wants_field("as_org", "AUTONOMOUS_SYSTEM_ORGANIZATION") {
                        if let Some(org) = asn.autonomous_system_organization {
                            let path = format!("[{}][as_org]", target_clean);
                            event.set(&path, org);
                        }
                    }
                    if self.wants_field("asn", "AUTONOMOUS_SYSTEM_NUMBER") {
                        if let Some(num) = asn.autonomous_system_number {
                            let path = format!("[{}][asn]", target_clean);
                            event.set(&path, num as i64);
                        }
                    }
                }
            } else if let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(ip) {
                if let Some(country) = &city.country {
                    if self.wants_field("country_code2", "COUNTRY_CODE2") {
                        if let Some(iso) = country.iso_code {
                            let path = format!("[{}][country_code2]", target_clean);
                            event.set(&path, iso);
                        }
                    }
                    if self.wants_field("country_name", "COUNTRY_NAME") {
                        if let Some(names) = &country.names {
                            if let Some(name) = names.get("en") {
                                let path = format!("[{}][country_name]", target_clean);
                                event.set(&path, *name);
                            }
                        }
                    }
                }
                if self.wants_field("continent_code", "CONTINENT_CODE") {
                    if let Some(continent) = &city.continent {
                        if let Some(code) = continent.code {
                            let path = format!("[{}][continent_code]", target_clean);
                            event.set(&path, code);
                        }
                    }
                }
                if self.wants_field("city_name", "CITY_NAME") {
                    if let Some(c) = &city.city {
                        if let Some(names) = &c.names {
                            if let Some(name) = names.get("en") {
                                let path = format!("[{}][city_name]", target_clean);
                                event.set(&path, *name);
                            }
                        }
                    }
                }
            }
        } else {
            let (country_code2, as_org) = lookup_public_geoip(&ip);

            if self.default_database_type.eq_ignore_ascii_case("ASN") {
                if self.wants_field("as_org", "AUTONOMOUS_SYSTEM_ORGANIZATION") {
                    let path = format!("[{}][as_org]", target_clean);
                    event.set(&path, as_org);
                }
            } else {
                if self.wants_field("country_code2", "COUNTRY_CODE2") {
                    let path = format!("[{}][country_code2]", target_clean);
                    event.set(&path, country_code2);
                }
            }
        }

        Ok(vec![event])
    }
}

const BUILTIN_GROK_PATTERNS: &[(&str, &str)] = &[
    // Base patterns
    ("USERNAME", r"[a-zA-Z0-9._-]+"),
    ("USER", r"%{USERNAME}"),
    ("WORD", r"\b\w+\b"),
    ("NUMBER", r"(?:[+-]?(?:[0-9]+(?:\.[0-9]+)?))"),
    ("INT", r"(?:[+-]?(?:[0-9]+))"),
    ("IP", r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)"),
    (
        "HOSTNAME",
        r"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(?:\.?|\b)",
    ),
    ("IPORHOST", r"(?:%{IP}|%{HOSTNAME})"),
    ("COMMONMAC", r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"),
    ("HTTPDATE", r"[^\]]+"),
    ("DATA", r".*?"),
    ("GREEDYDATA", r".*"),
    // dnsmasq patterns
    (
        "DHCPD",
        r"%{WORD:message_type}(\(%{WORD:interface}\))?\s*%{IP:source_ip}?\s*%{COMMONMAC:source_mac}?\s*%{HOSTNAME:source_hostname}?",
    ),
    (
        "DNSMASQ_QUERY",
        r"%{WORD:action_dns}\[%{WORD:action_opt}\]\s*%{IPORHOST:target_ip}\s*from\s*%{IPORHOST:source_ip}\s*",
    ),
    (
        "DNSMASQ_FORWARD",
        r"%{WORD:action_dns}\s*%{IPORHOST:domain}\s*to\s*%{IPORHOST:ip_forward}\s*",
    ),
    (
        "DNSMASQ_ACTION_IS",
        r"%{WORD:action_dns}\s*%{IPORHOST:target_dns}\s*is\s*<?%{IPORHOST:status_dns}>?\s*",
    ),
    // nginx pattern
    (
        "NGINXACCESS",
        r#"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:time}\] "%{WORD:request_action} %{DATA:request} HTTP/%{NUMBER:http_version}" %{NUMBER:response} %{NUMBER:bytes} "%{DATA:referrer}" "%{DATA:agent}""#,
    ),
    // iptables patterns
    ("IPTABLES_IN_DEVICE", r"(IN=%{WORD:iptables_in_device}?)"),
    ("IPTABLES_OUT_DEVICE", r"(OUT=%{WORD:iptables_out_device}?)"),
    ("IPTABLES_MAC_ADDRESS", r"(MAC=(?<mac_address>\S*))"),
    (
        "IPTABLES_ETHERNET",
        r"%{IPTABLES_IN_DEVICE}? %{IPTABLES_OUT_DEVICE}? %{IPTABLES_MAC_ADDRESS}?\s*",
    ),
    ("FRAGFLAG", r"(?:(?:CE|DF|MF)\s*)*"),
    ("IPTABLES_IP_SRC", r"SRC=%{IP:iptables_src_ip}"),
    ("IPTABLES_IP_DST", r"DST=%{IP:iptables_dst_ip}"),
    ("IPTABLES_IP_LEN", r"LEN=%{NUMBER:iptables_len}"),
    ("IPTABLES_IP_TOS", r"TOS=%{WORD:iptables_tos}"),
    ("IPTABLES_IP_PREC", r"PREC=%{WORD:iptables_prec}"),
    ("IPTABLES_IP_TTL", r"TTL=%{WORD:iptables_ttl}"),
    ("IPTABLES_IP_ID", r"(ID=%{NUMBER:iptables_id}?)"),
    ("IPTABLES_IP_FRAGFLAG", r"%{FRAGFLAG:iptables_fragment_flags}"),
    (
        "IPTABLES_IP",
        r"%{IPTABLES_IP_SRC}? %{IPTABLES_IP_DST}? %{IPTABLES_IP_LEN}? %{IPTABLES_IP_TOS}? %{IPTABLES_IP_PREC}? %{IPTABLES_IP_TTL}? %{IPTABLES_IP_ID}? %{IPTABLES_IP_FRAGFLAG}?\s*",
    ),
    ("IPTABLES_ICMP", r"TYPE=%{NUMBER:iptables_icmp_type}"),
    (
        "IPTABLES_PORTS",
        r"SPT=%{NUMBER:iptables_src_port} DPT=%{NUMBER:iptables_dst_port}",
    ),
    (
        "IPTABLES_UDP",
        r"%{IPTABLES_PORTS} LEN=%{NUMBER:iptables_udp_len}",
    ),
    ("IPTABLES_TCP", r"%{IPTABLES_PORTS}"),
    (
        "IPTABLES_PAYLOAD",
        r"PROTO=%{WORD:iptables_protocol} (%{IPTABLES_TCP}|%{IPTABLES_UDP}|%{IPTABLES_ICMP})",
    ),
    (
        "IPTABLES_MESSAGE",
        r"(?<status>\S+)\s+%{IPTABLES_ETHERNET}%{IPTABLES_IP}%{IPTABLES_PAYLOAD}",
    ),
    // sshd patterns
    (
        "SSHD_LISTEN",
        r"(?<listening_on_msg>Server listening on) %{IP:sshd_listen_ip} port %{NUMBER:sshd_listen_port}\.",
    ),
    (
        "SSHD_TERMINATE",
        r"Received signal %{NUMBER:sshd_signal}; %{WORD:terminate_msg}\.",
    ),
    (
        "SSHD_TUNN_ERR1",
        r"(?<connection_failed_msg>error: connect_to) %{IP:sshd_listen_ip} port %{NUMBER:sshd_listen_port}: failed\.",
    ),
    (
        "SSHD_TUNN_ERR2",
        r"(?<fail_listen_port_msg>error: channel_setup_fwd_listener: cannot listen to port:) %{NUMBER:sshd_listen_port}",
    ),
    (
        "SSHD_TUNN_ERR3",
        r"(?<address_already_in_use_msg>error: bind: Address already in use)",
    ),
    (
        "SSHD_TUNN_ERR4",
        r"(?<cannot_listen_to_port_msg>error: channel_setup_fwd_listener_tcpip: cannot listen to port): %{NUMBER:sshd_listen_port}",
    ),
    (
        "SSHD_TUNN_TIMEOUT",
        r"(?<timeout_msg>Timeout), client not responding\.",
    ),
    (
        "SSHD_SUCCESS",
        r"(?<sshd_success_connection_msg>(?<sshd_result>Accepted)) %{WORD:sshd_auth_type} for %{USERNAME:sshd_user} from %{IP:sshd_client_ip} port %{NUMBER:sshd_port} %{WORD:sshd_protocol}",
    ),
    (
        "SSHD_DISCONNECT",
        r"(?<received_disconnect_from_msg>Received disconnect from) %{IP:sshd_client_ip}:(%{NUMBER:sshd_port})? %{NUMBER:sshd_disconnect_code}: (?<sshd_disconnect_status>(\w+\s*)+)",
    ),
    (
        "SSHD_CONN_CLOSE",
        r"(?<connection_closed_msg>Connection closed by) %{IP:sshd_client_ip} \[(?<stage>.*)\]",
    ),
    (
        "SSHD_SESSION_OPEN",
        r"pam_unix\(sshd:session\): (?<session_open_msg>session opened for user) %{USERNAME:sshd_user} by \(uid=\d+\)",
    ),
    (
        "SSHD_SESSION_CLOSE",
        r"pam_unix\(sshd:session\): (?<session_closed_msg>session closed for user) %{USERNAME:sshd_user}",
    ),
    (
        "SSHD_SESSION_FAIL",
        r"pam_systemd\(sshd:session\): (?<session_fail_msg>Failed to release session): (?<sshd_disconnect_status>Interrupted system call)",
    ),
    (
        "SSHD_REFUSE_CONN",
        r"(?<sshd_result_conn_msg>(?<sshd_result>refused) connect from) %{DATA:sshd_client_hostname} \(%{IPORHOST:sshd_client_ip}\)",
    ),
    (
        "SSHD_FAIL",
        r"(?<sshd_fail_msg>Failed) %{WORD:sshd_auth_type} for %{USERNAME:sshd_invalid_user} from %{IP:sshd_client_ip} port %{NUMBER:sshd_port} %{WORD:sshd_protocol}",
    ),
    (
        "SSHD_USER_FAIL",
        r"(?<sshd_user_fail_msg>Failed password for invalid user) %{USERNAME:sshd_invalid_user} from %{IP:sshd_client_ip} port %{NUMBER:sshd_port} %{WORD:sshd_protocol}",
    ),
    (
        "SSHD_INVAL_USER",
        r"(?<sshd_invalid_user_msg>Invalid user)\s*%{USERNAME:sshd_invalid_user}? from %{IP:sshd_client_ip}",
    ),
    (
        "SSHD_MESSAGE",
        r"%{SSHD_LISTEN}|%{SSHD_TERMINATE}|%{SSHD_TUNN_ERR1}|%{SSHD_TUNN_ERR2}|%{SSHD_TUNN_ERR3}|%{SSHD_TUNN_ERR4}|%{SSHD_TUNN_TIMEOUT}|%{SSHD_SUCCESS}|%{SSHD_DISCONNECT}|%{SSHD_CONN_CLOSE}|%{SSHD_SESSION_OPEN}|%{SSHD_SESSION_CLOSE}|%{SSHD_SESSION_FAIL}|%{SSHD_REFUSE_CONN}|%{SSHD_FAIL}|%{SSHD_USER_FAIL}|%{SSHD_INVAL_USER}",
    ),
];

fn sanitize_lookarounds(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if i + 3 < chars.len()
            && chars[i] == '('
            && chars[i + 1] == '?'
            && chars[i + 2] == '<'
            && (chars[i + 3] == '=' || chars[i + 3] == '!')
        {
            let mut depth = 1usize;
            let mut j = i + 4;
            while j < chars.len() && depth > 0 {
                if chars[j] == '(' {
                    depth += 1;
                } else if chars[j] == ')' {
                    depth -= 1;
                }
                j += 1;
            }
            out.push_str("(?:)");
            i = j;
            continue;
        } else if i + 2 < chars.len()
            && chars[i] == '('
            && chars[i + 1] == '?'
            && (chars[i + 2] == '=' || chars[i + 2] == '!')
        {
            let mut depth = 1usize;
            let mut j = i + 3;
            while j < chars.len() && depth > 0 {
                if chars[j] == '(' {
                    depth += 1;
                } else if chars[j] == ')' {
                    depth -= 1;
                }
                j += 1;
            }
            out.push_str("(?:)");
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn load_patterns_from_dirs(dirs: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in BUILTIN_GROK_PATTERNS {
        map.insert((*k).to_string(), sanitize_lookarounds(v));
    }

    for dir in dirs {
        let path = Path::new(dir);
        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        if let Ok(content) = fs::read_to_string(&p) {
                            for line in content.lines() {
                                let trimmed = line.trim();
                                if trimmed.is_empty() || trimmed.starts_with('#') {
                                    continue;
                                }
                                if let Some((name, pat)) = trimmed.split_once(char::is_whitespace) {
                                    map.insert(
                                        name.trim().to_string(),
                                        sanitize_lookarounds(pat.trim()),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    map
}

fn split_top_level_alternatives(expr: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut escaped = false;

    for ch in expr.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            current.push(ch);
            escaped = true;
            continue;
        }
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' if bracket_depth > 0 => {
                bracket_depth -= 1;
                current.push(ch);
            }
            '(' if bracket_depth == 0 => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' if bracket_depth == 0 && paren_depth > 0 => {
                paren_depth -= 1;
                current.push(ch);
            }
            '{' if bracket_depth == 0 => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' if bracket_depth == 0 && brace_depth > 0 => {
                brace_depth -= 1;
                current.push(ch);
            }
            '|' if bracket_depth == 0 && paren_depth == 0 && brace_depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn find_next_grok_token(s: &str) -> Option<(usize, usize)> {
    let p_pct = s.find("%{");
    let p_dlr = s.find("${");
    match (p_pct, p_dlr) {
        (Some(p1), Some(p2)) => {
            if p1 <= p2 {
                Some((p1, 2))
            } else {
                Some((p2, 2))
            }
        }
        (Some(p1), None) => Some((p1, 2)),
        (None, Some(p2)) => Some((p2, 2)),
        (None, None) => None,
    }
}

fn expand_grok_to_alternatives(
    pattern: &str,
    patterns: &HashMap<String, String>,
    depth: usize,
) -> Vec<String> {
    if depth > 32 {
        return vec![pattern.to_string()];
    }

    let top_alts = split_top_level_alternatives(pattern);
    if top_alts.is_empty() {
        return vec![pattern.to_string()];
    }
    if top_alts.len() > 1 {
        let mut all = Vec::new();
        for alt in top_alts {
            all.extend(expand_grok_to_alternatives(&alt, patterns, depth + 1));
        }
        return all;
    }

    let single = &top_alts[0];
    let Some((start, token_len)) = find_next_grok_token(single) else {
        return vec![single.clone()];
    };
    let after_start = &single[start + token_len..];
    let Some(end_offset) = after_start.find('}') else {
        return vec![single.clone()];
    };

    let prefix = &single[..start];
    let token = &after_start[..end_offset];
    let suffix = &after_start[end_offset + 1..];

    let mut parts = token.split(':');
    let pat_name = parts.next().unwrap_or("");
    let field_name = parts.next();

    let raw_def = patterns
        .get(pat_name)
        .cloned()
        .or_else(|| std::env::var(pat_name).ok())
        .unwrap_or_else(|| r".*?".to_string());

    let def_alts = expand_grok_to_alternatives(&raw_def, patterns, depth + 1);
    let mut results = Vec::new();

    for def_alt in def_alts {
        let replacement = if let Some(field) = field_name.filter(|f| !f.is_empty()) {
            format!("(?P<{}>{})", field, def_alt)
        } else {
            format!("(?:{})", def_alt)
        };
        let combined = format!("{}{}{}", prefix, replacement, suffix);
        results.extend(expand_grok_to_alternatives(&combined, patterns, depth + 1));
    }

    results
}

fn deduplicate_capture_names(regex_str: &str) -> (String, HashMap<String, String>) {
    let mut out = String::with_capacity(regex_str.len());
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut alias_to_field: HashMap<String, String> = HashMap::new();
    let chars: Vec<char> = regex_str.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            out.push(chars[i]);
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }

        // Check for (?P<name> or (?<name>
        let prefix_len = if i + 4 < chars.len()
            && chars[i] == '('
            && chars[i + 1] == '?'
            && chars[i + 2] == 'P'
            && chars[i + 3] == '<'
        {
            Some(4)
        } else if i + 3 < chars.len()
            && chars[i] == '('
            && chars[i + 1] == '?'
            && chars[i + 2] == '<'
            && chars[i + 3] != '='
            && chars[i + 3] != '!'
        {
            Some(3)
        } else {
            None
        };

        if let Some(plen) = prefix_len {
            let name_start = i + plen;
            let mut name_end = name_start;
            while name_end < chars.len() && chars[name_end] != '>' {
                name_end += 1;
            }
            if name_end < chars.len() {
                let orig_name: String = chars[name_start..name_end].iter().collect();
                let count = counts.entry(orig_name.clone()).or_insert(0);
                *count += 1;
                let unique_name = if *count == 1 {
                    orig_name.clone()
                } else {
                    format!("{}__dup{}", orig_name, *count)
                };
                alias_to_field.insert(unique_name.clone(), orig_name);
                out.push_str("(?P<");
                out.push_str(&unique_name);
                out.push('>');
                i = name_end + 1;
                continue;
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    (out, alias_to_field)
}

#[derive(Debug, Clone)]
pub struct CompiledGrokPattern {
    pub regex: Regex,
    pub capture_names: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct GrokFilter {
    pub matches: Vec<(String, Vec<CompiledGrokPattern>)>,
}

impl GrokFilter {
    pub fn from_config(block: &PluginBlock) -> anyhow::Result<Self> {
        let patterns_dirs = block.get_string_list("patterns_dir").unwrap_or_default();
        let pattern_bank = load_patterns_from_dirs(&patterns_dirs);

        let mut matches = Vec::new();
        for (key, val) in &block.settings {
            if key == "match" {
                let pairs = config_value_to_cfg_pairs(val);
                for (field, pat_cfg) in pairs {
                    let raw_patterns = config_value_to_string_list(&pat_cfg);
                    let mut compiled_list = Vec::new();
                    for raw_pat in raw_patterns {
                        let expanded_alts =
                            expand_grok_to_alternatives(&raw_pat, &pattern_bank, 0);
                        for alt in expanded_alts {
                            let (dedup_str, alias_map) = deduplicate_capture_names(&alt);
                            let sanitized = sanitize_lookarounds(&dedup_str);
                            let regex = Regex::new(&sanitized)?;
                            let capture_names = regex
                                .capture_names()
                                .flatten()
                                .map(|cap| {
                                    let field_name = alias_map
                                        .get(cap)
                                        .cloned()
                                        .unwrap_or_else(|| cap.to_string());
                                    (cap.to_string(), field_name)
                                })
                                .collect();
                            compiled_list.push(CompiledGrokPattern {
                                regex,
                                capture_names,
                            });
                        }
                    }
                    matches.push((field, compiled_list));
                }
            }
        }

        Ok(Self { matches })
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        Self::from_config(block).unwrap_or_default()
    }
}

impl Filter for GrokFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        for (field, compiled_patterns) in &self.matches {
            let Some(text) = event.get_str(field) else {
                continue;
            };
            let mut matched_this_field = false;
            for compiled in compiled_patterns {
                if let Some(caps) = compiled.regex.captures(&text) {
                    for (cap_name, field_name) in &compiled.capture_names {
                        if let Some(m) = caps.name(cap_name) {
                            let val_str = m.as_str().trim_end();
                            if !val_str.is_empty() {
                                event.set(field_name, val_str);
                            }
                        }
                    }
                    matched_this_field = true;
                    break;
                }
            }
            if !matched_this_field {
                event.tag("_grokparsefailure");
            }
        }
        Ok(vec![event])
    }
}

#[derive(Debug, Clone)]
pub struct FingerprintFilter {
    pub source: String,
    pub target: String,
    pub key: String,
    pub method: String,
}

impl Default for FingerprintFilter {
    fn default() -> Self {
        Self {
            source: "message".to_string(),
            target: "fingerprint".to_string(),
            key: String::new(),
            method: "SHA256".to_string(),
        }
    }
}

impl FingerprintFilter {
    pub fn from_config(block: &PluginBlock) -> anyhow::Result<Self> {
        let source = block.get_str("source").unwrap_or("message").to_string();
        let target = block
            .get_str("target")
            .unwrap_or("fingerprint")
            .to_string();
        let key = block.get_str("key").unwrap_or("").to_string();
        let method = block.get_str("method").unwrap_or("SHA256").to_string();

        Ok(Self {
            source,
            target,
            key,
            method,
        })
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        Self::from_config(block).unwrap_or_default()
    }
}

impl Filter for FingerprintFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        if let Some(src_val) = event.get_str(&self.source) {
            let mut hasher = Sha256::new();
            hasher.update(src_val.as_bytes());
            hasher.update(self.key.as_bytes());
            let hex_digest = hex::encode(hasher.finalize());
            event.set(&self.target, hex_digest);
        }
        Ok(vec![event])
    }
}

#[derive(Debug, Clone, Default)]
pub struct DropFilter;

impl DropFilter {
    pub fn from_config(_block: &PluginBlock) -> anyhow::Result<Self> {
        Ok(Self)
    }

    pub fn from_block(_block: &PluginBlock) -> Self {
        Self
    }
}

impl Filter for DropFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        event.cancel();
        Ok(vec![])
    }
}

#[derive(Debug, Clone)]
pub struct JsonFilter {
    pub source: String,
    pub target: Option<String>,
}

impl JsonFilter {
    pub fn from_config(block: &PluginBlock) -> anyhow::Result<Self> {
        let source = block
            .get_str("source")
            .map(|s| s.to_string())
            .or_else(|| {
                block.get_string_list("source").and_then(|mut list| list.pop())
            })
            .unwrap_or_else(|| "message".to_string());
        let target = block
            .get_str("target")
            .map(|s| s.to_string())
            .or_else(|| {
                block.get_string_list("target").and_then(|mut list| list.pop())
            });

        Ok(Self { source, target })
    }

    pub fn from_block(block: &PluginBlock) -> Self {
        Self::from_config(block).unwrap_or_else(|_| Self {
            source: "message".to_string(),
            target: None,
        })
    }
}

impl Filter for JsonFilter {
    fn process(&self, mut event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        let json_str_opt = match event.get(&self.source) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };

        let Some(json_str) = json_str_opt else {
            return Ok(vec![event]);
        };

        match serde_json::from_str::<Value>(&json_str) {
            Ok(parsed) => {
                if let Some(target) = &self.target {
                    event.set(target, parsed);
                } else if let Value::Object(map) = parsed {
                    for (k, v) in map {
                        event.set(&k, v);
                    }
                } else {
                    event.tag("_jsonparsefailure");
                }
            }
            Err(_) => {
                event.tag("_jsonparsefailure");
            }
        }

        Ok(vec![event])
    }
}

pub fn from_plugin_block(block: &PluginBlock) -> anyhow::Result<Option<Box<dyn Filter>>> {
    let filter: Box<dyn Filter> = match block.name.as_str() {
        "mutate" => Box::new(MutateFilter::from_config(block)?),
        "cidr" => Box::new(CidrFilter::from_config(block)?),
        "geoip" => Box::new(GeoipFilter::from_config(block)?),
        "grok" => Box::new(GrokFilter::from_config(block)?),
        "fingerprint" => Box::new(FingerprintFilter::from_config(block)?),
        "drop" => Box::new(DropFilter::from_config(block)?),
        "json" => Box::new(JsonFilter::from_config(block)?),
        _ => return Ok(None),
    };
    Ok(Some(filter))
}
