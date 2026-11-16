#!/bin/sh
# Seeds the Spanner emulator over its REST API, `conformance` included
# (src/db/conformance.rs). The emulator keeps nothing on
# disk and its image has no shell, so this runs beside it on every start, then
# leaves a marker for the healthcheck and stays up.
set -eu

api="http://spanner:9020/v1"
project="projects/dbdelve-dev"
instance="$project/instances/dev"
database="$instance/databases/dbdelve_dev"

# The body on stdin, from a quoted heredoc, so a quote in it needs nothing.
post() {
  curl -fsS -X POST -H 'content-type: application/json' "$api/$1" --data-binary @-
}

until curl -fsS "$api/$project/instanceConfigs" >/dev/null 2>&1; do sleep 1; done

# Already seeded: the emulator outlived this container.
if ! curl -fsS "$api/$database" >/dev/null 2>&1; then
  post "$project/instances" >/dev/null <<'JSON' || true
{"instanceId": "dev", "instance": {"config": "emulator-config", "displayName": "dev", "nodeCount": 1}}
JSON
  post "$instance/databases" >/dev/null <<'JSON'
{
    "createStatement": "CREATE DATABASE `dbdelve_dev`",
    "extraStatements": [
      "CREATE TABLE singers (id INT64 NOT NULL, name STRING(MAX), born DATE, score NUMERIC, raw BYTES(MAX), tags ARRAY<STRING(MAX)>, doc JSON, ok BOOL, f FLOAT64, seen TIMESTAMP OPTIONS (allow_commit_timestamp = true), up STRING(MAX) AS (UPPER(name)) STORED) PRIMARY KEY (id)",
      "CREATE TABLE albums (id INT64 NOT NULL, album_id INT64 NOT NULL, title STRING(100) DEFAULT ('untitled'), note STRING(MAX), CONSTRAINT fk_singer FOREIGN KEY (id) REFERENCES singers (id)) PRIMARY KEY (id, album_id), INTERLEAVE IN PARENT singers ON DELETE CASCADE",
      "CREATE UNIQUE INDEX albums_by_title ON albums (title) STORING (note)",
      "CREATE VIEW singer_names SQL SECURITY INVOKER AS SELECT s.id, s.name FROM singers AS s",
      "CREATE TABLE labels (name STRING(64) NOT NULL, note STRING(MAX), rank INT64, made DATE) PRIMARY KEY (name)",
      "CREATE TABLE conformance (id INT64 NOT NULL, label STRING(MAX) NOT NULL, whole INT64, fraction NUMERIC, ratio FLOAT64, flag BOOL, day DATE, moment TIMESTAMP, bytes BYTES(MAX)) PRIMARY KEY (id)"
    ]}
JSON
  until curl -fsS "$api/$database" | grep -q '"READY"'; do sleep 1; done
  # A single-use transaction's mutations need no transaction id to commit.
  session=$(echo '{}' | post "$database/sessions" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
  post "$session:commit" >/dev/null <<'JSON'
{
    "singleUseTransaction": {"readWrite": {}},
    "mutations": [
      {"insert": {"table": "singers",
        "columns": ["id", "name", "born", "score", "raw", "tags", "doc", "ok", "f", "seen"],
        "values": [
          ["1", "it's \\ a\nb", "2020-01-02", "1.5", "YWJj", ["x", "y"], "{\"a\":1}", true, 1.25, "2020-01-02T03:04:05Z"],
          ["2", null, null, null, null, null, null, null, "NaN", null]
        ]}},
      {"insert": {"table": "labels", "columns": ["name", "note", "rank", "made"],
        "values": [
          ["alpha", "first", "1", "2026-01-01"],
          ["it's", "a quote in the key", "2", null]
        ]}},
      {"insert": {"table": "conformance",
        "columns": ["id", "label", "whole", "fraction", "ratio", "flag", "day", "moment", "bytes"],
        "values": [
          ["1", "alpha", "9007199254740993", "12.50", 0.5, true, "2024-02-29", "2024-02-29T12:34:56Z", "AP8="],
          ["2", "Zoë 李 🐉 'quoted'", "-42", "-0.01", -1.25, false, "1999-12-31", "1999-12-31T23:59:59Z", "3q2+7w=="],
          ["3", "nulls", null, null, null, null, null, null, null]
        ]}}
    ]}
JSON
fi

touch /tmp/dbdelve-seeded
exec sleep infinity
