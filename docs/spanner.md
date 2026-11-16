# Spanner

DBDelve talks to Google Cloud Spanner over its REST API. It reads GoogleSQL
databases, pipe syntax included, on the service or on the emulator. This page
is what you need to know before filling in the form, and what does not work
yet.

## Signing in

Which credential is used is decided by which field is filled in:

| Emulator | Key file | Signs in with |
| --- | --- | --- |
| filled | either | nothing: plain HTTP to the emulator |
| blank | filled | the service account key in that file |
| blank | blank | your application default credentials |

- **A service account key** is the JSON file Google Cloud gives you for one.
  DBDelve signs its own short-lived token with it, so no request goes to a
  token endpoint. The path has to be **absolute**; the profile stores the path
  and nothing else.
- **Application default credentials** are found the way Google's own tools
  look for them: the file `GOOGLE_APPLICATION_CREDENTIALS` names, else
  `application_default_credentials.json` in the directory `CLOUDSDK_CONFIG`
  names, else in `~/.config/gcloud` (`%APPDATA%\gcloud` on Windows). That is
  the file `gcloud auth application-default login` writes. A user's sign-in is
  billed to the file's `quota_project_id` when it has one.
- **Not supported:** the metadata server, workload identity federation
  (`external_account`) and impersonated service accounts. A credentials file
  of another type is refused by name.

## The form

| Field | |
| --- | --- |
| Project | The Google Cloud project id. |
| Instance | The Spanner instance id. |
| Database | Required. A profile browses one database; Select Database lists the instance's others. |
| Key file | Absolute path to a service account's JSON key. Blank uses application default credentials. |
| Emulator | The emulator's **REST** address, such as `localhost:9020`. Not the gRPC port `SPANNER_EMULATOR_HOST` names. Blank reaches the service over HTTPS. |
| Statement timeout | Seconds the client waits for an answer that has gone quiet. Blank is no limit. |

There is no connection URL for Spanner; fill the fields in instead.

## Things that behave differently here

- **Each run is its own transaction.** A read runs in a read-only transaction,
  a write in a read-write one committed at once, a schema change as an
  operation DBDelve waits on. `BEGIN` and `COMMIT` are not Spanner statements,
  and Spanner says so. A run of several `INSERT`, `UPDATE` and `DELETE`
  statements is one transaction: all of it applies or none of it does.
- **A run mixing reads, writes and schema changes is refused.** Spanner sends
  each through a different call. Run each kind on its own.
- **Read-only holds on the server.** Every statement goes in a read-only
  transaction, which refuses a write in Spanner's own words, and a schema
  change is refused before anything is sent.
- **Numbers and `BOOL` are written bare** (`42`, `-1.5`, `TRUE`), since
  GoogleSQL reads a quoted value as a number nowhere. A table keyed by
  `BYTES` stays read-only and says why, and `JSON`, `ARRAY` and `BYTES`
  columns are not editable in the grid.
- **Filters read every column as text** (`CAST(col AS STRING)`), which
  Spanner refuses for `JSON` and `ARRAY` columns.
- **Most DDL asks before it runs.** DBDelve's parser does not read Spanner's
  `STRING(MAX)`, `INTERLEAVE IN PARENT`, `STORING`, statement hints or `THEN
  RETURN`, so it cannot say what such a statement does and asks once.
- **Cancel** ends DBDelve's wait for a read at once. A cancelled schema change
  keeps whatever Spanner had applied of it.
- **The default schema has no name.** Its tables are listed under an empty
  schema and written without one.
- **Not listed:** routines, sequences, change streams and interleaving.
- **Not offered:** Explain, PostgreSQL-dialect databases (refused at connect),
  partitioned DML, stale reads, SSH and SSM tunnels, and a proxy from the
  environment.
- **`BYTES`** are shown as Spanner sends them, base64. An `ARRAY` or `STRUCT`
  is written out as JSON.

## The emulator

`docker compose up -d` starts one on port 59020 with a seeded `dbdelve-dev`
project, `dev` instance and `dbdelve_dev` database. The emulator does not read
pipe syntax, and it keeps running a query after DBDelve has cancelled it.
