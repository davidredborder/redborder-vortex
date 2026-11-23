use redborder_vortex::config::DaemonConfig;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_daemon_config_yaml_parsing_and_redis_url_auth() {
    let test_path = PathBuf::from("/tmp/test_vortex_cfg.yml");
    fs::write(
        &test_path,
        r#"
path.settings: "/etc/logstash"
pipelines.yml: "/etc/logstash/pipelines.yml"
ipc.socket: "/run/redborder-vortex/redborder-vortex.sock"
redis.url: "redis://redis.service:26379"
redis.password: "supersecretredis"
postgres.host: "master.postgresql.service"
postgres.port: 5432
postgres.database: "redborder"
postgres.user: "redborder"
postgres.password: "secretpg"
"#,
    )
    .unwrap();

    let cfg = DaemonConfig::load_from_file(&test_path).expect("Should parse YAML config");
    let _ = fs::remove_file(&test_path);

    assert_eq!(cfg.path_settings.as_deref(), Some("/etc/logstash"));
    assert_eq!(
        cfg.ipc_socket.as_deref(),
        Some("/run/redborder-vortex/redborder-vortex.sock")
    );
    assert_eq!(cfg.redis_url.as_deref(), Some("redis://redis.service:26379"));
    assert_eq!(cfg.redis_password.as_deref(), Some("supersecretredis"));
    assert_eq!(cfg.postgres_host.as_deref(), Some("master.postgresql.service"));
    assert_eq!(cfg.postgres_port, Some(5432));
    assert_eq!(cfg.postgres_database.as_deref(), Some("redborder"));
    assert_eq!(cfg.postgres_user.as_deref(), Some("redborder"));
    assert_eq!(cfg.postgres_password.as_deref(), Some("secretpg"));

    let full_url = cfg.full_redis_url().unwrap();
    assert_eq!(
        full_url,
        "redis://:supersecretredis@redis.service:26379"
    );
}

#[test]
fn test_daemon_config_already_embedded_password() {
    let test_path = PathBuf::from("/tmp/test_vortex_cfg2.yml");
    fs::write(
        &test_path,
        r#"
redis.url: "redis://:existingpass@redis.service:26379"
redis.password: "overrideignored"
"#,
    )
    .unwrap();

    let cfg = DaemonConfig::load_from_file(&test_path).expect("Should parse YAML config");
    let _ = fs::remove_file(&test_path);

    let full_url = cfg.full_redis_url().unwrap();
    assert_eq!(full_url, "redis://:existingpass@redis.service:26379");
}

#[test]
fn test_state_store_redis_eager_connection_failure() {
    // Attempting to connect to an unused port should fail eagerly
    let res = redborder_vortex::state::StateStore::new_with_redis("redis://127.0.0.1:1");
    assert!(res.is_err(), "Should eagerly fail connection to unreachable Redis");
}

#[test]
fn test_daemon_config_password_special_characters_encoded() {
    let test_path = PathBuf::from("/tmp/test_vortex_cfg3.yml");
    fs::write(
        &test_path,
        r#"
redis.url: "redis://redis.service:26379"
redis.password: "p@ss:w/rd%123"
"#,
    )
    .unwrap();

    let cfg = DaemonConfig::load_from_file(&test_path).expect("Should parse YAML config");
    let _ = fs::remove_file(&test_path);

    let full_url = cfg.full_redis_url().unwrap();
    assert_eq!(
        full_url,
        "redis://:p%40ss%3Aw%2Frd%25123@redis.service:26379"
    );
}

#[test]
fn test_daemon_config_nmsp_triangulation_parsing() {
    let test_path = PathBuf::from("/tmp/test_vortex_cfg_nmsp.yml");
    fs::write(
        &test_path,
        r#"
nmsp.triangulation: true
nmsp.triangulation_min_aps: 3
"#,
    )
    .unwrap();

    let cfg = DaemonConfig::load_from_file(&test_path).expect("Should parse YAML config");
    let _ = fs::remove_file(&test_path);

    assert_eq!(cfg.nmsp_triangulation, Some(true));
    assert_eq!(cfg.nmsp_triangulation_min_aps, Some(3));
}

#[test]
fn test_daemon_config_merge_preserves_base_credentials_when_overlay_lacks_them() {
    let mut base = DaemonConfig {
        redis_url: Some("redis://redis.cluster:26379".to_string()),
        redis_password: Some("secret123".to_string()),
        postgres_host: Some("master.postgresql.service".to_string()),
        postgres_port: Some(5432),
        postgres_database: Some("redborder".to_string()),
        postgres_user: Some("redborder".to_string()),
        postgres_password: Some("pgpass".to_string()),
        nmsp_triangulation: Some(true),
        nmsp_triangulation_min_aps: Some(2),
        ..Default::default()
    };

    let overlay = DaemonConfig {
        path_settings: Some("/etc/logstash".to_string()),
        pipelines_yml: Some("/etc/logstash/pipelines.yml".to_string()),
        nmsp_triangulation_min_aps: Some(4), // explicit override
        ..Default::default()
    };

    base.merge(overlay);

    // Overlay values applied
    assert_eq!(base.path_settings.as_deref(), Some("/etc/logstash"));
    assert_eq!(base.pipelines_yml.as_deref(), Some("/etc/logstash/pipelines.yml"));
    assert_eq!(base.nmsp_triangulation_min_aps, Some(4));

    // Base values preserved
    assert_eq!(base.redis_url.as_deref(), Some("redis://redis.cluster:26379"));
    assert_eq!(base.redis_password.as_deref(), Some("secret123"));
    assert_eq!(base.postgres_host.as_deref(), Some("master.postgresql.service"));
    assert_eq!(base.postgres_database.as_deref(), Some("redborder"));
    assert_eq!(base.postgres_user.as_deref(), Some("redborder"));
    assert_eq!(base.postgres_password.as_deref(), Some("pgpass"));
    assert_eq!(base.nmsp_triangulation, Some(true));
}

#[test]
fn test_daemon_config_resolve_merges_system_config_and_settings_dir() {
    use std::fs;
    let pid = std::process::id();
    let temp_base_dir = PathBuf::from(format!("/tmp/test_vortex_base_dir_{}", pid));
    let temp_settings_dir = PathBuf::from(format!("/tmp/test_vortex_settings_dir_{}", pid));

    let _ = fs::create_dir_all(&temp_base_dir);
    let _ = fs::create_dir_all(&temp_settings_dir);

    // Base system config has DB and redis
    fs::write(
        temp_base_dir.join("config.yml"),
        r#"
redis.url: "redis://cluster:26379"
redis.password: "clusterpass"
postgres.host: "pg.cluster"
postgres.database: "redborder"
nmsp.triangulation: true
"#,
    )
    .unwrap();

    // Logstash settings dir only has logstash pipelines
    fs::write(
        temp_settings_dir.join("logstash.yml"),
        r#"
pipeline.workers: 4
path.settings: "/etc/logstash"
"#,
    )
    .unwrap();

    let resolved = DaemonConfig::resolve(&temp_settings_dir, &temp_base_dir)
        .expect("Should resolve merged config");

    assert_eq!(resolved.redis_url.as_deref(), Some("redis://cluster:26379"));
    assert_eq!(resolved.redis_password.as_deref(), Some("clusterpass"));
    assert_eq!(resolved.postgres_host.as_deref(), Some("pg.cluster"));
    assert_eq!(resolved.postgres_database.as_deref(), Some("redborder"));
    assert_eq!(resolved.nmsp_triangulation, Some(true));
    assert_eq!(resolved.path_settings.as_deref(), Some("/etc/logstash"));

    // Explicit file should NOT inherit base system config
    let standalone_file = temp_settings_dir.join("standalone.yml");
    fs::write(
        &standalone_file,
        r#"
path.settings: "/opt/custom"
nmsp.triangulation: false
"#,
    )
    .unwrap();

    let resolved_standalone = DaemonConfig::resolve(&standalone_file, &temp_base_dir)
        .expect("Should resolve standalone config");
    assert_eq!(resolved_standalone.path_settings.as_deref(), Some("/opt/custom"));
    assert_eq!(resolved_standalone.redis_url, None, "Standalone file must not inherit base Redis");
    assert_eq!(resolved_standalone.postgres_host, None, "Standalone file must not inherit base PG");
    assert_eq!(resolved_standalone.nmsp_triangulation, Some(false));

    // Redis URL change in overlay without password drops base password
    let mut base_with_pass = DaemonConfig {
        redis_url: Some("redis://old.host:26379".to_string()),
        redis_password: Some("old_secret".to_string()),
        ..Default::default()
    };
    let overlay_new_host = DaemonConfig {
        redis_url: Some("redis://new.host:26379".to_string()),
        ..Default::default()
    };
    base_with_pass.merge(overlay_new_host);
    assert_eq!(base_with_pass.redis_url.as_deref(), Some("redis://new.host:26379"));
    assert_eq!(base_with_pass.redis_password, None, "Password must not leak to new endpoint");

    let _ = fs::remove_dir_all(&temp_base_dir);
    let _ = fs::remove_dir_all(&temp_settings_dir);
}

#[test]
fn test_daemon_config_redis_url_env_var_fallback() {
    let cfg = DaemonConfig {
        redis_url: Some("redis://redis.service:26379".to_string()),
        redis_password: None,
        ..Default::default()
    };

    // When no env var is set, plain URL is returned
    std::env::remove_var("REDIS_PASSWORD");
    assert_eq!(cfg.full_redis_url(), Some("redis://redis.service:26379".to_string()));

    // When REDIS_PASSWORD env var is set, it is injected into the URL
    std::env::set_var("REDIS_PASSWORD", "envsecret123");
    assert_eq!(
        cfg.full_redis_url(),
        Some("redis://:envsecret123@redis.service:26379".to_string())
    );
    std::env::remove_var("REDIS_PASSWORD");
}
