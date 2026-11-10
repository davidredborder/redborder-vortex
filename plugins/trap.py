import json

LOCATION_FIELDS = [
    "deployment", "deployment_uuid", "namespace", "namespace_uuid", "market", "market_uuid",
    "organization", "organization_uuid", "service_provider", "service_provider_uuid",
    "campus", "campus_uuid", "building", "building_uuid", "floor", "floor_uuid"
]

KEEP_FIELDS = set([
    "sensor_name", "sensor_ip", "host", "oid", "version", "sensor_uuid", "proxy_uuid", "timestamp"
] + LOCATION_FIELDS)

DROP_FROM_MESSAGE = set([
    "sensor_uuid", "index_partitions", "index_replicas", "timestamp", "version", "host",
    "sensor_name", "proxy_uuid", "reqid", "security_model"
] + LOCATION_FIELDS)


def normalize_trap(event, config=None):
    """
    Implements trap/10_normalize.conf:
    1. Builds raw_message JSON excluding drop_from_message fields.
    2. Drops top-level fields not in keep_fields.
    3. Sets 'message' to the formatted raw_message.
    """
    raw_message = event.get("message")
    if raw_message is None:
        full = event.to_dict() if hasattr(event, "to_dict") else {}
        full.pop("@timestamp", None)
        full.pop("@version", None)
        raw_message = json.dumps(full)

    if isinstance(raw_message, str):
        try:
            parsed = json.loads(raw_message)
            if isinstance(parsed, dict):
                kept = {k: v for k, v in parsed.items() if k not in DROP_FROM_MESSAGE}
                raw_message = json.dumps(kept)
        except Exception:
            pass

    # Prune event fields
    event_dict = event.to_dict() if hasattr(event, "to_dict") else {}
    for k in list(event_dict.keys()):
        if k not in KEEP_FIELDS:
            event.remove(k)

    event.set("message", raw_message)
    return event


def filter(event, state=None):
    return normalize_trap(event)
