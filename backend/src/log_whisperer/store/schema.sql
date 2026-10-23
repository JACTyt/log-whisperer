CREATE SEQUENCE IF NOT EXISTS event_seq START 1;

CREATE TABLE IF NOT EXISTS events (
    event_id     VARCHAR PRIMARY KEY,
    seq          BIGINT DEFAULT nextval('event_seq'),
    ts           TIMESTAMP NOT NULL,
    source_type  VARCHAR NOT NULL,
    channel      VARCHAR,
    host         VARCHAR,
    "user"       VARCHAR,
    src_ip       VARCHAR,
    dst_ip       VARCHAR,
    process      VARCHAR,
    command_line VARCHAR,
    action       VARCHAR,
    outcome      VARCHAR,
    event_code   VARCHAR,
    source_file  VARCHAR NOT NULL,
    record_ref   VARCHAR NOT NULL,
    raw          VARCHAR NOT NULL,
    fields       JSON
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id VARCHAR PRIMARY KEY,
    rule_id      VARCHAR NOT NULL,
    rule_title   VARCHAR NOT NULL,
    rule_source  VARCHAR NOT NULL,
    severity     VARCHAR NOT NULL,
    techniques   VARCHAR[],
    event_ids    VARCHAR[],
    ts_first     TIMESTAMP NOT NULL,
    ts_last      TIMESTAMP NOT NULL,
    hosts        VARCHAR[],
    users        VARCHAR[],
    src_ips      VARCHAR[]
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id       VARCHAR PRIMARY KEY,
    title             VARCHAR NOT NULL,
    ts_start          TIMESTAMP NOT NULL,
    ts_end            TIMESTAMP NOT NULL,
    severity          VARCHAR NOT NULL,
    hosts             VARCHAR[],
    users             VARCHAR[],
    src_ips           VARCHAR[],
    techniques        VARCHAR[],
    detection_ids     VARCHAR[],
    context_event_ids VARCHAR[],
    updated_at        TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS live_offsets (
    source  VARCHAR PRIMARY KEY,
    counter BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS narratives (
    incident_id VARCHAR NOT NULL,
    model       VARCHAR NOT NULL,
    created_at  TIMESTAMP NOT NULL,
    body        JSON NOT NULL,
    rejected    JSON NOT NULL
);
