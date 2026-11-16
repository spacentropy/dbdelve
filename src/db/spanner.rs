//! Google Cloud Spanner, over its REST API.
//!
//! No gRPC and no client library: Google's Rust clients are tokio futures,
//! which panic on GPUI's executor, and the REST surface is the same service
//! spoken as JSON. So this is a blocking `ureq` client in the manner of
//! `snowflake.rs`, with a token it signs or exchanges itself.
//!
//! Stateless autocommit. Each submission is its own transaction: a read in a
//! single-use read-only one, a write in a read-write one committed at once,
//! DDL as a long-running operation. `BEGIN` and `COMMIT` are not Spanner
//! statements, so a typed one gets the server's own error.

mod auth;
#[cfg(test)]
mod mock;

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sqlparser::dialect::BigQueryDialect;
use sqlparser::tokenizer::{Token, Tokenizer};
use ureq::Agent;
use ureq::http::Response;
use ureq::tls::TlsConfig;

use self::auth::Auth;
use super::clickhouse::http::{self, Bounds, Stop, Watch};
use super::{
    CancelToken, Cancelling, Catalog, Column, Databases, DbError, EditTarget, Engine, Fetch,
    ForeignKey, Index, IndexKind, NamedDefinition, QueryResult, Row, Stopped, Structure,
    assemble_catalog, assemble_foreign_keys, assemble_structure, optional_cell, plain_error,
    required_cell, terminated,
};
use crate::sql::{Buffer, Projected, table_read};
use crate::tls::SslMode;

/// What a Cancel's error says, which is how `is_cancel` knows it.
pub(super) const CANCELLED: &str = "Cancelled.";

/// What it takes to reach one Spanner database.
///
/// Which credential signs the requests is said by which field is filled: an
/// emulator takes none, a key file signs as its service account, and with
/// neither the platform's application default credentials are used.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpannerConfig {
    pub project: String,
    pub instance: String,
    pub database: String,
    /// Absolute path to a service account's JSON key, or blank for
    /// application default credentials. A path and not a secret, so it lives
    /// in the profile and the Keychain holds nothing for this engine.
    pub private_key: String,
    /// The emulator's REST address, `host:port`, or blank for the service.
    /// Plain HTTP because the field says emulator, never because the host
    /// looks local (hard rule 3).
    pub emulator: String,
    /// Seconds, or 0 for no bound. The client's, on the response: Spanner
    /// takes no per-statement timeout over REST.
    pub statement_timeout: u32,
}

impl SpannerConfig {
    /// What was being talked to, for an error or a title to name.
    pub fn endpoint(&self) -> String {
        let path = format!("{}/{}/{}", self.project, self.instance, self.database);
        match self.emulator.trim() {
            "" => path,
            emulator => format!("{path} on {emulator}"),
        }
    }
}

/// A literal for a value bound for a column of `data_type`, where GoogleSQL
/// will not convert a string: it converts a string literal to `DATE` and
/// `TIMESTAMP` and nothing else, so `id = '1'` is refused for an `INT64`.
/// A number goes out bare for the numeric types and `true`/`false` for
/// `BOOL`, and only when the value is exactly such a literal; anything else
/// falls back to a quoted string and the server's own refusal.
pub(super) fn typed_literal(value: &str, data_type: &str) -> Option<String> {
    let name = data_type
        .split('(')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (whole, fraction) = match unsigned.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (unsigned, None),
    };
    let decimal = digits(whole) && fraction.is_none_or(digits);
    let exact = match name.as_str() {
        "INT64" => digits(unsigned) && value.parse::<i64>().is_ok(),
        "NUMERIC" => decimal,
        "FLOAT64" | "FLOAT32" => {
            let mantissa = unsigned.split(['e', 'E']).next().unwrap_or_default();
            // `1.` would parse, and the gate's bare number has digits after a point.
            mantissa
                .split_once('.')
                .map_or(digits(mantissa), |(whole, fraction)| {
                    digits(whole) && digits(fraction)
                })
                && value.parse::<f64>().is_ok_and(f64::is_finite)
        }
        "BOOL" => matches!(value, "true" | "false"),
        _ => false,
    };
    exact.then(|| value.to_string())
}

/// The service, verified against the platform's trust store.
const SERVICE: &str = "https://spanner.googleapis.com/v1/";

/// How many times a write the server aborted is run again, whole.
const ABORTED_TRIES: u32 = 5;

/// How often a schema change's operation is asked whether it is done.
const POLL: Duration = match cfg!(test) {
    true => Duration::from_millis(20),
    false => Duration::from_millis(500),
};

/// Which of Spanner's APIs carries a statement, by its first keyword after
/// comments and a leading `@{…}` hint, as Google's own clients choose.
///
/// Transport, not a gate: a write sent as a read is refused by the read-only
/// transaction it lands in, and nothing that opens with a write keyword is a
/// read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Read,
    Write,
    Ddl,
}

fn route(statement: &str) -> Route {
    let Ok(tokens) = Tokenizer::new(&BigQueryDialect {}, statement).tokenize() else {
        return Route::Read;
    };
    let mut words = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .peekable();
    // The tokenizer reads `@{NAME` as one word, or as `@` and `{`.
    let hinted = match words.peek() {
        Some(Token::AtSign) => true,
        Some(Token::Word(word)) => word.value.starts_with("@{"),
        _ => false,
    };
    if hinted {
        for token in words.by_ref() {
            if *token == Token::RBrace {
                break;
            }
        }
    }
    let Some(Token::Word(word)) = words.next() else {
        return Route::Read;
    };
    match word.value.to_ascii_uppercase().as_str() {
        "INSERT" | "UPDATE" | "DELETE" => Route::Write,
        "CREATE" | "ALTER" | "DROP" | "GRANT" | "REVOKE" | "RENAME" | "ANALYZE" => Route::Ddl,
        _ => Route::Read,
    }
}

/// Whether a submission goes to the DDL endpoint, whose cancel leaves what it
/// had applied.
pub(super) fn changes_schema(sql: &str) -> bool {
    statements(sql)
        .iter()
        .any(|statement| route(statement) == Route::Ddl)
}

/// The statements of a submission, each without the `;` that separates it:
/// the DDL endpoint refuses one, and each API takes one statement a request.
fn statements(sql: &str) -> Vec<&str> {
    Buffer::for_engine(Engine::Spanner, sql)
        .statements()
        .iter()
        .map(|range| &sql[range.clone()])
        .collect()
}

/// What the server said, with what a retry needs to know.
#[derive(Debug)]
struct Refused {
    /// gRPC's name for it: `ABORTED`, `NOT_FOUND`. Empty where none was said.
    status: String,
    error: DbError,
}

impl Refused {
    fn aborted(&self) -> bool {
        self.status == "ABORTED"
    }

    /// The session expired or was deleted, so the request never ran.
    fn session_gone(&self) -> bool {
        self.status == "NOT_FOUND" && self.error.message.contains("Session not found")
    }
}

impl From<DbError> for Refused {
    fn from(error: DbError) -> Self {
        Self {
            status: String::new(),
            error,
        }
    }
}

/// gRPC's codes by number, as the emulator's bare errors carry them.
fn status_name(code: i64) -> &'static str {
    match code {
        1 => "CANCELLED",
        3 => "INVALID_ARGUMENT",
        4 => "DEADLINE_EXCEEDED",
        5 => "NOT_FOUND",
        6 => "ALREADY_EXISTS",
        7 => "PERMISSION_DENIED",
        9 => "FAILED_PRECONDITION",
        10 => "ABORTED",
        13 => "INTERNAL",
        14 => "UNAVAILABLE",
        16 => "UNAUTHENTICATED",
        _ => "",
    }
}

/// An error in either shape Spanner sends one: `{"error": {code, message,
/// status}}` from the service and the emulator's stream, a bare `{code,
/// message}` from the emulator's other calls. `None` for anything else.
fn error_of(body: &Value, sql: Option<&str>) -> Option<Refused> {
    let error = match body.get("error") {
        Some(error) if error.is_object() => error,
        _ => body,
    };
    let message = error.get("message")?.as_str()?;
    let status = match error["status"].as_str() {
        Some(status) => status.to_string(),
        None => status_name(error["code"].as_i64().unwrap_or_default()).to_string(),
    };
    Some(Refused {
        status,
        error: DbError {
            message: message.to_string(),
            position: sql.and_then(|sql| position(message, sql)),
        },
    })
}

/// The byte offset a message's `[at line:column]` names in `sql`.
fn position(message: &str, sql: &str) -> Option<usize> {
    let at = message.rfind("[at ")?;
    let (line, column) = message[at + 4..].split_once(']')?.0.split_once(':')?;
    let (line, column): (usize, usize) = (line.parse().ok()?, column.parse().ok()?);
    let start = sql
        .split_inclusive('\n')
        .take(line.checked_sub(1)?)
        .map(str::len)
        .sum::<usize>();
    let offset = sql[start..]
        .char_indices()
        .nth(column.checked_sub(1)?)
        .map_or(sql.len() - start, |(offset, _)| offset);
    Some(start + offset)
}

/// The top-level JSON objects of a response body, read as they arrive: the
/// service streams a JSON array of results, the emulator one object a line.
/// A `result` wrapper is taken off, and an `error` element ends the stream.
struct Messages<R> {
    reader: R,
    buffer: Vec<u8>,
    ended: bool,
}

impl<R: Read> Messages<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
            ended: false,
        }
    }

    /// The next object, `None` at the end of the body.
    fn next(&mut self) -> Result<Option<Value>, DbError> {
        loop {
            if let Some((start, end)) = whole_object(&self.buffer)? {
                let object: Value =
                    serde_json::from_slice(&self.buffer[start..end]).map_err(|error| {
                        plain_error(format!(
                            "A result from Spanner was not understood: {error}."
                        ))
                    })?;
                self.buffer.drain(..end);
                return Ok(Some(match object.get("result") {
                    Some(result) => result.clone(),
                    None => object,
                }));
            }
            if self.ended {
                return match self.buffer.iter().all(|byte| b" \t\r\n[],".contains(byte)) {
                    true => Ok(None),
                    false => Err(plain_error(
                        "The result from Spanner was cut off part way.".into(),
                    )),
                };
            }
            let mut chunk = [0; 16 * 1024];
            let read = self.reader.read(&mut chunk).map_err(|error| DbError {
                message: format!("The result from Spanner was not read whole: {error}."),
                position: None,
            })?;
            self.ended = read == 0;
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Where the first complete top-level object in `bytes` starts and ends, if
/// one has arrived. Between objects only an array's punctuation may stand.
fn whole_object(bytes: &[u8]) -> Result<Option<(usize, usize)>, DbError> {
    let (mut depth, mut in_string, mut escaped, mut start) = (0usize, false, false, None);
    for (index, &byte) in bytes.iter().enumerate() {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' if depth > 0 => in_string = true,
            b'{' | b'[' if depth > 0 => depth += 1,
            b'{' => {
                start = Some(index);
                depth = 1;
            }
            b'}' | b']' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    return Ok(start.map(|start| (start, index + 1)));
                }
            }
            _ if depth > 0 => {}
            b' ' | b'\t' | b'\r' | b'\n' | b'[' | b']' | b',' => {}
            _ => {
                return Err(plain_error(
                    "The result from Spanner was not the JSON it should be.".into(),
                ));
            }
        }
    }
    Ok(None)
}

/// A value split across messages put back together: strings concatenate,
/// lists concatenate with their touching elements merged by the same rule
/// when those are strings, lists or objects, and objects merge field by
/// field.
fn merged(first: Value, second: Value) -> Value {
    match (first, second) {
        (Value::String(mut first), Value::String(second)) => {
            first.push_str(&second);
            Value::String(first)
        }
        (Value::Array(mut first), Value::Array(second)) => {
            let mut second = second.into_iter();
            let mergeable =
                |value: &Value| value.is_string() || value.is_array() || value.is_object();
            match (first.pop(), second.next()) {
                (Some(last), Some(next)) if mergeable(&last) => first.push(merged(last, next)),
                (last, next) => first.extend(last.into_iter().chain(next)),
            }
            first.extend(second);
            Value::Array(first)
        }
        (Value::Object(mut first), Value::Object(second)) => {
            for (name, value) in second {
                let value = match first.remove(&name) {
                    Some(existing) => merged(existing, value),
                    None => value,
                };
                first.insert(name, value);
            }
            Value::Object(first)
        }
        // A bool, number or null is never chunked.
        (_, second) => second,
    }
}

/// A type as GoogleSQL spells it: `INT64`, `ARRAY<STRING>`,
/// `STRUCT<a INT64, b STRING>`.
fn type_name(kind: &Value) -> String {
    match kind["code"].as_str().unwrap_or_default() {
        "ARRAY" => format!("ARRAY<{}>", type_name(&kind["arrayElementType"])),
        "STRUCT" => format!(
            "STRUCT<{}>",
            fields(kind)
                .iter()
                .map(|field| match field["name"].as_str() {
                    Some(name) if !name.is_empty() => {
                        format!("{name} {}", type_name(&field["type"]))
                    }
                    _ => type_name(&field["type"]),
                })
                .collect::<Vec<_>>()
                .join(", ")
        ),
        code => code.to_string(),
    }
}

fn fields(kind: &Value) -> &[Value] {
    kind["structType"]["fields"]
        .as_array()
        .map_or(&[], Vec::as_slice)
}

/// A value as text: a scalar as the server sent it, which is already its
/// text (`INT64`, `NUMERIC`, dates and timestamps arrive as strings, `BYTES`
/// as base64 and shown as that), and an `ARRAY` or `STRUCT` written out as
/// JSON, element by element by its type. `None` is NULL.
fn render(value: &Value, kind: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Array(_) | Value::Object(_) => Some(nested(value, kind)),
    }
}

fn nested(value: &Value, kind: &Value) -> String {
    let code = kind["code"].as_str().unwrap_or_default();
    match value {
        Value::Null => "null".into(),
        Value::Array(items) if code == "STRUCT" => {
            let fields = fields(kind);
            let pairs: Vec<String> = items
                .iter()
                .enumerate()
                .map(|(at, item)| {
                    let field = fields.get(at).unwrap_or(&Value::Null);
                    let name = field["name"].as_str().filter(|name| !name.is_empty());
                    let name = name.map_or_else(|| format!("_{}", at + 1), str::to_string);
                    format!("{}: {}", Value::from(name), nested(item, &field["type"]))
                })
                .collect();
            format!("{{{}}}", pairs.join(", "))
        }
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|item| nested(item, &kind["arrayElementType"]))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::String(text) => match code {
            "INT64" | "NUMERIC" | "FLOAT64" | "FLOAT32" => text.clone(),
            _ => Value::from(text.as_str()).to_string(),
        },
        other => other.to_string(),
    }
}

/// What a streamed statement left behind beside its rows.
struct Streamed {
    result: QueryResult,
    /// The transaction a `begin` opened.
    transaction: Option<String>,
}

/// Takes a run's handle back out of its token, and its watch out of the
/// connection's, however the request ends.
struct Running<'a> {
    token: &'a Mutex<Cancelling>,
    watches: &'a Mutex<HashMap<String, Arc<AtomicBool>>>,
    handle: String,
}

impl<'a> Running<'a> {
    /// A Cancel already asked drops the statement unsent.
    fn register(
        cancel: &'a CancelToken,
        watches: &'a Mutex<HashMap<String, Arc<AtomicBool>>>,
        abort: &Arc<AtomicBool>,
    ) -> Result<Self, DbError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let handle = format!("spanner-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let mut token = lock(&cancel.0);
        if token.asked {
            return Err(plain_error(CANCELLED.into()));
        }
        lock(watches).insert(handle.clone(), Arc::clone(abort));
        token.handles.push(handle.clone());
        Ok(Self {
            token: &cancel.0,
            watches,
            handle,
        })
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        lock(self.token)
            .handles
            .retain(|handle| *handle != self.handle);
        lock(self.watches).remove(&self.handle);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One run's watch: what Cancel aborts, and the idle bound its reads keep.
struct Run {
    abort: Arc<AtomicBool>,
    watch: Watch,
    bounds: Bounds,
}

impl Run {
    fn new(bounds: Bounds) -> Self {
        let abort = Arc::<AtomicBool>::default();
        Self {
            watch: Watch::new(Arc::clone(&abort), bounds.limit()),
            abort,
            bounds,
        }
    }

    fn aborted(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }
}

/// A connection in name only, as Snowflake's is: the profile, a client, the
/// token, and the sessions requests run in.
#[derive(Clone)]
pub struct Connection {
    config: Arc<SpannerConfig>,
    /// `https://spanner.googleapis.com/v1/`, or the emulator's.
    base: Arc<str>,
    /// `projects/{p}/instances/{i}/databases/{d}`.
    database: Arc<str>,
    agent: Agent,
    auth: Arc<Auth>,
    read_only: Arc<AtomicBool>,
    /// The multiplexed session every read shares: it takes any number at once.
    reads: Arc<Mutex<Option<String>>>,
    /// A regular session for writes, held for the whole of one: a session
    /// takes one transaction at a time, and the emulator one in all.
    writes: Arc<Mutex<Option<String>>>,
    running: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl Connection {
    pub fn open(config: &SpannerConfig) -> Result<Self, DbError> {
        let emulator = config.emulator.trim();
        match emulator {
            "" => Self::open_at(config, SERVICE, auth::credential(&config.private_key)?),
            emulator => Self::open_at(
                config,
                &format!("http://{emulator}/v1/"),
                auth::Credential::Emulator,
            ),
        }
    }

    /// Against `base`, which a test points at the mock.
    fn open_at(
        config: &SpannerConfig,
        base: &str,
        credential: auth::Credential,
    ) -> Result<Self, DbError> {
        for (label, value) in [
            ("project", &config.project),
            ("instance", &config.instance),
            ("database", &config.database),
        ] {
            if value.trim().is_empty() {
                return Err(plain_error(format!("A Spanner profile needs a {label}.")));
            }
        }
        let tls = match base.starts_with("https://") {
            true => http::tls_config(SslMode::VerifyFull, None)?,
            false => TlsConfig::default(),
        };
        let connection = Self {
            database: format!(
                "projects/{}/instances/{}/databases/{}",
                config.project.trim(),
                config.instance.trim(),
                config.database.trim()
            )
            .into(),
            config: Arc::new(config.clone()),
            base: base.into(),
            agent: http::watched_agent(tls, None, Bounds::internal()),
            auth: Arc::new(Auth::new(credential)),
            read_only: Arc::default(),
            reads: Arc::default(),
            writes: Arc::default(),
            running: Arc::default(),
        };
        // Connecting is the connection test: the credential, the database
        // and the session, in one read that also says which dialect it is.
        let dialect = connection.internal_query(DIALECT_SQL)?;
        if dialect.rows.first().and_then(|row| row.get(0)) == Some("POSTGRESQL") {
            return Err(plain_error(format!(
                "{} is a PostgreSQL-dialect database, which DBDelve does not speak to yet: it \
                 reads GoogleSQL databases only.",
                connection.config.database
            )));
        }
        Ok(connection)
    }

    /// A session on `database` of this connection's instance, sharing only
    /// the agent and the token: sessions belong to one database, so its reads,
    /// writes and running requests are its own. It starts under this
    /// connection's hold, and the caller applies every later one. No dialect
    /// check, since [`Self::databases`] lists no PostgreSQL-dialect database.
    pub(super) fn on_database(&self, database: &str) -> Self {
        let config = SpannerConfig {
            database: database.to_string(),
            ..(*self.config).clone()
        };
        Self {
            database: format!(
                "projects/{}/instances/{}/databases/{}",
                config.project.trim(),
                config.instance.trim(),
                config.database.trim()
            )
            .into(),
            config: Arc::new(config),
            read_only: Arc::new(AtomicBool::new(self.read_only.load(Ordering::SeqCst))),
            reads: Arc::default(),
            writes: Arc::default(),
            running: Arc::default(),
            ..self.clone()
        }
    }

    pub fn set_read_only(&self, read_only: bool) -> Result<(), DbError> {
        self.read_only.store(read_only, Ordering::SeqCst);
        Ok(())
    }

    /// Stop the requests running under `cancel`: a read ends where it is, a
    /// write is rolled back before its commit, and a schema change is asked
    /// to cancel.
    pub fn cancel(&self, cancel: &CancelToken) -> Result<(), DbError> {
        let handles = {
            let mut token = lock(&cancel.0);
            token.asked = true;
            token.handles.clone()
        };
        let watches = lock(&self.running);
        for handle in handles {
            if let Some(abort) = watches.get(&handle) {
                abort.store(true, Ordering::SeqCst);
            }
        }
        Ok(())
    }

    /// Run a submission as typed, each statement by the API its first
    /// keyword picks, keeping what `fetch` asks for of the last's rows.
    pub fn query(
        &self,
        sql: &str,
        cancel: &CancelToken,
        fetch: Fetch,
    ) -> Result<QueryResult, DbError> {
        let _held = fetch.hold()?;
        let run = Run::new(Bounds::user(self.config.statement_timeout));
        let _running = Running::register(cancel, &self.running, &run.abort)?;
        self.submit(sql, &run, fetch)
    }

    fn internal_query(&self, sql: &str) -> Result<QueryResult, DbError> {
        self.read(sql, &Run::new(Bounds::internal()), Fetch::default())
    }

    fn submit(&self, sql: &str, run: &Run, fetch: Fetch) -> Result<QueryResult, DbError> {
        let started = Instant::now();
        let statements = statements(sql);
        let routes: Vec<Route> = statements
            .iter()
            .map(|statement| route(statement))
            .collect();
        // Held on the server: every statement goes in a read-only
        // transaction, which takes no DML, and the DDL endpoint, which no
        // transaction holds, is not reached at all.
        if self.read_only.load(Ordering::SeqCst) {
            if routes.contains(&Route::Ddl) {
                return Err(plain_error(
                    "Read-only keeps this connection to reads, and a schema change is not one: \
                     Spanner runs it outside any transaction a read could hold."
                        .into(),
                ));
            }
        } else if routes.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(plain_error(
                "Spanner runs reads, writes and schema changes through different calls, so a \
                 submission mixing them is refused. Run each kind on its own."
                    .into(),
            ));
        }
        let mut result = match routes.first() {
            None => return Ok(QueryResult::default()),
            Some(Route::Write) if !self.read_only.load(Ordering::SeqCst) => {
                self.write(&statements, run, fetch)?
            }
            Some(Route::Ddl) if !self.read_only.load(Ordering::SeqCst) => {
                self.schema_change(&statements, run)?
            }
            Some(_) => {
                let (last, earlier) = statements.split_last().expect("one at least");
                for statement in earlier {
                    self.read(statement, run, Fetch::default())?;
                }
                let mut result = self.read(last, run, fetch)?;
                if earlier.is_empty() && !result.columns.is_empty() {
                    (result.edit, result.read_only_reason) =
                        self.edit_target(last, &result.columns);
                }
                result
            }
        };
        if result.elapsed.is_zero() {
            result.elapsed = started.elapsed();
        }
        Ok(result)
    }

    /// One statement in a single-use read-only transaction, on the shared
    /// session.
    fn read(&self, sql: &str, run: &Run, fetch: Fetch) -> Result<QueryResult, DbError> {
        let transaction = json!({"singleUse": {"readOnly": {"strong": true}}});
        // Stopped only where the caller says it is the submission's one
        // stoppable statement, as on every engine.
        let attempt = |session: &str| {
            self.stream(
                session,
                sql,
                transaction.clone(),
                None,
                run,
                fetch,
                fetch.reads_only,
            )
        };
        let session = self.session(&self.reads, true, run)?;
        let streamed = match attempt(&session) {
            Err(refused) if refused.session_gone() => {
                self.forget(&self.reads, &session);
                attempt(&self.session(&self.reads, true, run)?)
            }
            streamed => streamed,
        };
        streamed
            .map(|streamed| streamed.result)
            .map_err(|refused| refused.error)
    }

    /// DML in one read-write transaction committed at once: one statement
    /// streamed, so `THEN RETURN` rows arrive as they come, several as one
    /// `executeBatchDml`, applied whole or not at all. Run again whole, a
    /// few times, when the server aborts it: a self-contained submission is
    /// safe to replay.
    fn write(&self, statements: &[&str], run: &Run, fetch: Fetch) -> Result<QueryResult, DbError> {
        let mut slot = lock(&self.writes);
        let mut pause = Duration::from_millis(50);
        let mut tries = 0;
        loop {
            let session = match slot.clone() {
                Some(session) => session,
                None => {
                    let session = self.create_session(false, run)?;
                    *slot = Some(session.clone());
                    session
                }
            };
            match self.write_once(&session, statements, run, fetch) {
                Err(refused) if refused.session_gone() && tries == 0 => *slot = None,
                Err(refused) if refused.aborted() && tries + 1 < ABORTED_TRIES => {
                    std::thread::sleep(pause);
                    pause *= 2;
                }
                outcome => return outcome.map_err(|refused| refused.error),
            }
            tries += 1;
            if run.aborted() {
                return Err(plain_error(CANCELLED.into()));
            }
        }
    }

    fn write_once(
        &self,
        session: &str,
        statements: &[&str],
        run: &Run,
        fetch: Fetch,
    ) -> Result<QueryResult, Refused> {
        let begin = json!({"begin": {"readWrite": {}}});
        let (mut result, transaction) = match statements {
            [statement] => {
                // Drained and counted past the limit: the rows are a write's.
                let streamed = self.stream(session, statement, begin, Some(1), run, fetch, false);
                let streamed = streamed?;
                (streamed.result, streamed.transaction)
            }
            _ => self.batch(session, statements, begin, run)?,
        };
        let transaction = transaction.ok_or_else(|| {
            Refused::from(plain_error(
                "Spanner ran the write and named no transaction to commit; nothing was \
                 committed."
                    .into(),
            ))
        })?;
        // The last moment a Cancel undoes the write.
        if run.aborted() {
            self.rollback(session, &transaction);
            return Err(plain_error(CANCELLED.into()).into());
        }
        // Unwatched: a commit cut off part way leaves nobody knowing whether
        // it landed.
        let commit = Run::new(Bounds::internal());
        let _watching = commit.watch.enter();
        self.json(
            "POST",
            &format!("{session}:commit"),
            Some(&json!({"transactionId": transaction})),
            commit.bounds,
            None,
        )?;
        result.elapsed = Duration::ZERO;
        Ok(result)
    }

    /// Several DML statements as one batch in one transaction. A statement
    /// that fails stops the batch, and the transaction is rolled back.
    fn batch(
        &self,
        session: &str,
        statements: &[&str],
        begin: Value,
        run: &Run,
    ) -> Result<(QueryResult, Option<String>), Refused> {
        let body = json!({
            "transaction": begin,
            "seqno": "1",
            "statements": statements.iter().map(|sql| json!({"sql": sql})).collect::<Vec<_>>(),
        });
        let _watching = run.watch.enter();
        let answer = self
            .json(
                "POST",
                &format!("{session}:executeBatchDml"),
                Some(&body),
                run.bounds,
                None,
            )
            .map_err(|refused| self.cancelled(run, refused))?;
        let sets = answer["resultSets"]
            .as_array()
            .map_or(&[][..], Vec::as_slice);
        let transaction = sets
            .first()
            .and_then(|set| set["metadata"]["transaction"]["id"].as_str())
            .map(str::to_string);
        if let Some(mut refused) = error_of(&answer["status"], None)
            .filter(|_| answer["status"]["code"].as_i64().unwrap_or_default() != 0)
        {
            if let Some(transaction) = &transaction {
                self.rollback(session, transaction);
            }
            let failed = sets.len();
            refused.error = DbError {
                position: statements
                    .get(failed)
                    .and_then(|sql| position(&refused.error.message, sql)),
                message: format!(
                    "Statement {} of {} failed, and none of the batch was applied: {}",
                    failed + 1,
                    statements.len(),
                    refused.error.message
                ),
            };
            return Err(refused);
        }
        let rows = sets
            .iter()
            .filter_map(|set| set["stats"]["rowCountExact"].as_str()?.parse::<u64>().ok())
            .sum();
        Ok((
            QueryResult {
                rows_affected: Some(rows),
                ..QueryResult::default()
            },
            transaction,
        ))
    }

    /// Best effort: a transaction left open expires on the server anyway.
    fn rollback(&self, session: &str, transaction: &str) {
        let run = Run::new(Bounds::internal());
        let _watching = run.watch.enter();
        let _ = self.json(
            "POST",
            &format!("{session}:rollback"),
            Some(&json!({"transactionId": transaction})),
            run.bounds,
            None,
        );
    }

    /// DDL as one long-running operation, waited on until it is done. A
    /// Cancel asks the operation to stop; what it had applied stays.
    fn schema_change(&self, statements: &[&str], run: &Run) -> Result<QueryResult, DbError> {
        let _watching = run.watch.enter();
        let mut operation = self
            .json(
                "PATCH",
                &format!("{}/ddl", self.database),
                Some(&json!({"statements": statements})),
                Bounds::internal(),
                statements
                    .first()
                    .copied()
                    .filter(|_| statements.len() == 1),
            )
            .map_err(|refused| refused.error)?;
        let name = operation["name"].as_str().unwrap_or_default().to_string();
        while operation["done"].as_bool() != Some(true) {
            if run.aborted() {
                let cancel = Run::new(Bounds::internal());
                let _watching = cancel.watch.enter();
                let outcome = match self.json(
                    "POST",
                    &format!("{name}:cancel"),
                    Some(&json!({})),
                    cancel.bounds,
                    None,
                ) {
                    Ok(_) => "Asked Spanner to stop the schema change.".to_string(),
                    Err(refused) => format!(
                        "Asking Spanner to stop the schema change failed ({}); it may still be \
                         running.",
                        refused.error.message
                    ),
                };
                return Err(plain_error(format!("{CANCELLED} {outcome}")));
            }
            std::thread::sleep(POLL);
            let poll = Run::new(Bounds::internal());
            let _watching = poll.watch.enter();
            operation = self
                .json("GET", &name, None, poll.bounds, None)
                .map_err(|refused| refused.error)?;
        }
        if let Some(refused) = error_of(&operation["error"], None) {
            return Err(refused.error);
        }
        Ok(QueryResult::default())
    }

    /// The session in `slot`, made if there is none.
    fn session(
        &self,
        slot: &Mutex<Option<String>>,
        multiplexed: bool,
        run: &Run,
    ) -> Result<String, DbError> {
        let mut slot = lock(slot);
        if let Some(session) = slot.as_ref() {
            return Ok(session.clone());
        }
        let session = self.create_session(multiplexed, run)?;
        *slot = Some(session.clone());
        Ok(session)
    }

    /// Forgets `session`, unless another request already replaced it.
    fn forget(&self, slot: &Mutex<Option<String>>, session: &str) {
        let mut slot = lock(slot);
        if slot.as_deref() == Some(session) {
            *slot = None;
        }
    }

    fn create_session(&self, multiplexed: bool, run: &Run) -> Result<String, DbError> {
        let body = match multiplexed {
            true => json!({"session": {"multiplexed": true}}),
            false => json!({}),
        };
        let _watching = run.watch.enter();
        let session = self
            .json(
                "POST",
                &format!("{}/sessions", self.database),
                Some(&body),
                Bounds::internal(),
                None,
            )
            .map_err(|refused| self.cancelled(run, refused).error)?;
        session["name"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| plain_error("Spanner made a session and did not name it.".into()))
    }

    /// One statement through `executeStreamingSql`, its rows kept as `fetch`
    /// asks. Past the limit a `stoppable` read ends there; otherwise the rest
    /// are read and counted.
    #[allow(clippy::too_many_arguments)]
    fn stream(
        &self,
        session: &str,
        sql: &str,
        transaction: Value,
        seqno: Option<u64>,
        run: &Run,
        fetch: Fetch,
        stoppable: bool,
    ) -> Result<Streamed, Refused> {
        let started = Instant::now();
        let mut body = json!({"sql": sql, "transaction": transaction});
        if let Some(seqno) = seqno {
            body["seqno"] = json!(seqno.to_string());
        }
        let _watching = run.watch.enter();
        let response = self
            .send(
                "POST",
                &format!("{session}:executeStreamingSql"),
                Some(&body),
                run.bounds,
                Some(sql),
            )
            .map_err(|refused| self.cancelled(run, refused))?;
        let mut messages = Messages::new(response.into_body().into_reader());
        let mut result = QueryResult::default();
        let mut kinds: Vec<Value> = Vec::new();
        let mut transaction = None;
        let mut pending: Vec<Value> = Vec::new();
        let mut chunked = false;
        let (mut returned, mut kept, mut filled, mut stopped) = (0, 0, None, false);
        let full = |kept: usize| fetch.limit.is_some_and(|limit| kept >= limit);
        loop {
            let message = match messages.next() {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(error) => return Err(self.cancelled(run, error.into())),
            };
            if let Some(refused) = message
                .get("error")
                .and_then(|_| error_of(&message, Some(sql)))
            {
                return Err(refused);
            }
            if let Some(metadata) = message.get("metadata") {
                if let Some(id) = metadata["transaction"]["id"].as_str() {
                    transaction = Some(id.to_string());
                }
                if kinds.is_empty()
                    && let Some(declared) = metadata["rowType"]["fields"].as_array()
                {
                    kinds = declared.iter().map(|field| field["type"].clone()).collect();
                    result.columns = declared
                        .iter()
                        .map(|field| Column {
                            name: field["name"].as_str().unwrap_or_default().to_string(),
                            data_type: Some(type_name(&field["type"])),
                        })
                        .collect();
                    if let Some(feed) = fetch.feed {
                        feed.begin(result.columns.clone());
                    }
                }
            }
            if let Some(count) = message["stats"]["rowCountExact"].as_str() {
                result.rows_affected = count.parse().ok();
            }
            let mut values = match message.get("values") {
                Some(Value::Array(values)) => values.clone().into_iter(),
                _ => Vec::new().into_iter(),
            };
            if chunked && let (Some(last), Some(next)) = (pending.pop(), values.next()) {
                pending.push(merged(last, next));
            }
            pending.extend(values);
            chunked = message["chunkedValue"].as_bool() == Some(true);
            let width = kinds.len().max(1);
            // A chunked last value is not whole until a later message.
            let whole = pending.len() - usize::from(chunked);
            let mut rows = whole / width;
            let complete: Vec<Value> = pending.drain(..rows * width).collect();
            for cells in complete.chunks(width) {
                rows -= 1;
                returned += 1;
                if full(kept) {
                    if stoppable {
                        stopped = true;
                        break;
                    }
                    continue;
                }
                let row = Row::new(
                    cells
                        .iter()
                        .zip(&kinds)
                        .map(|(value, kind)| render(value, kind)),
                )
                .map_err(Refused::from)?;
                kept += 1;
                if full(kept) {
                    filled = Some(started.elapsed());
                    if let Some(feed) = fetch.feed {
                        feed.fill();
                    }
                }
                result.bytes += row.text_len();
                match fetch.feed {
                    Some(feed) => feed.push(row),
                    None => result.rows.push(row),
                }
            }
            let _ = rows;
            if stopped {
                break;
            }
        }
        if stopped {
            result.stopped = Some(Stopped::AtLimit);
        } else {
            result.capped_from = (returned > kept).then_some(returned);
        }
        result.elapsed = match filled {
            Some(filled) if stopped || result.capped_from.is_some() => filled,
            _ => started.elapsed(),
        };
        Ok(Streamed {
            result,
            transaction,
        })
    }

    /// A Cancel's failure in its own words, which is how `is_cancel` knows
    /// it; and an idle response in words that say so.
    fn cancelled(&self, run: &Run, refused: Refused) -> Refused {
        match run.watch.stopped() {
            Some(Stop::Aborted) => plain_error(CANCELLED.into()).into(),
            Some(Stop::Idle) => plain_error(format!(
                "Spanner sent nothing for {} seconds; the statement was stopped.",
                run.bounds.limit().unwrap_or_default().as_secs()
            ))
            .into(),
            None => refused,
        }
    }

    /// One request, answered as JSON.
    fn json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        bounds: Bounds,
        sql: Option<&str>,
    ) -> Result<Value, Refused> {
        let mut response = self.send(method, path, body, bounds, sql)?;
        let bytes = response
            .body_mut()
            .with_config()
            .limit(u64::MAX)
            .read_to_vec()
            .map_err(|error| {
                plain_error(format!("Spanner's answer was not read whole: {error}."))
            })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            plain_error(format!("Spanner's answer was not understood: {error}.")).into()
        })
    }

    /// One request, its failure read whatever shape it came in.
    fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        bounds: Bounds,
        sql: Option<&str>,
    ) -> Result<Response<ureq::Body>, Refused> {
        let url = format!("{}{path}", self.base);
        let headers = self.auth.headers(&self.agent)?;
        macro_rules! sent {
            ($request:expr) => {{
                let mut request = $request
                    .config()
                    .timeout_recv_response(bounds.limit())
                    .build();
                for (name, value) in &headers {
                    request = request.header(*name, value.as_str());
                }
                request
            }};
        }
        let sent = match (method, body) {
            ("POST", Some(body)) => sent!(self.agent.post(&url)).send_json(body),
            ("PATCH", Some(body)) => sent!(self.agent.patch(&url)).send_json(body),
            _ => sent!(self.agent.get(&url)).call(),
        };
        let endpoint = self.config.endpoint();
        let mut response = sent.map_err(|error| {
            plain_error(format!("Spanner at {endpoint} was not reached: {error}."))
        })?;
        let status = response.status().as_u16();
        if status == 200 {
            return Ok(response);
        }
        let text = response.body_mut().read_to_string().unwrap_or_default();
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Err(error_of(&body, sql).unwrap_or_else(|| Refused {
            status: match status {
                404 => "NOT_FOUND",
                409 => "ABORTED",
                _ => "",
            }
            .to_string(),
            // The emulator drops a statement's error text over REST and
            // answers with an empty body.
            error: plain_error(format!(
                "Spanner answered HTTP {status} and said nothing more about why."
            )),
        }))
    }

    pub fn catalog(&self) -> Result<Catalog, DbError> {
        assemble_catalog(self.internal_query(RELATIONS_SQL)?, QueryResult::default())
    }

    pub fn databases(&self) -> Result<Databases, DbError> {
        let instance = self
            .database
            .rsplit_once("/databases/")
            .map_or(&*self.database, |(instance, _)| instance)
            .to_string();
        let mut names = Vec::new();
        let mut page = String::new();
        loop {
            let run = Run::new(Bounds::internal());
            let _watching = run.watch.enter();
            let query = match page.is_empty() {
                true => String::new(),
                false => format!("?pageToken={page}"),
            };
            let listed = self
                .json(
                    "GET",
                    &format!("{instance}/databases{query}"),
                    None,
                    run.bounds,
                    None,
                )
                .map_err(|refused| refused.error)?;
            for database in listed["databases"].as_array().into_iter().flatten() {
                // Only the dialect DBDelve reads; a PostgreSQL one would be
                // refused once moved onto.
                if database["databaseDialect"].as_str() == Some("POSTGRESQL") {
                    continue;
                }
                if let Some(name) = database["name"]
                    .as_str()
                    .and_then(|name| name.rsplit('/').next())
                {
                    names.push(name.to_string());
                }
            }
            match listed["nextPageToken"].as_str() {
                Some(next) if !next.is_empty() => page = next.to_string(),
                _ => break,
            }
        }
        Ok(Databases {
            names,
            current: Some(self.config.database.trim().to_string()),
        })
    }

    pub fn structure(&self, schema: &str, relation: &str) -> Result<Structure, DbError> {
        let literal = |value: &str| Engine::Spanner.quote_literal(value);
        let fill = |template: &str| {
            template
                .replace("{schema}", &literal(schema))
                .replace("{relation}", &literal(relation))
        };
        let columns = self.internal_query(&fill(COLUMNS_SQL))?;
        let index_columns = self.internal_query(&fill(INDEX_COLUMNS_SQL))?;
        let foreign = self.internal_query(&fill(FOREIGN_KEYS_SQL))?;
        let mut structure =
            assemble_structure(columns, QueryResult::default(), QueryResult::default())?;
        structure.foreign_keys = assemble_foreign_keys(&foreign)?;

        let cell =
            |row: &Row, name: &str| required_cell(&index_columns, row, name).map(str::to_string);
        let mut indexes: Vec<(String, IndexKind, Vec<String>)> = Vec::new();
        for row in &index_columns.rows {
            let name = cell(row, "index_name")?;
            let kind = match (
                cell(row, "index_type")?.as_str(),
                cell(row, "is_unique")?.as_str(),
            ) {
                ("PRIMARY_KEY", _) => IndexKind::Primary,
                (_, "true") => IndexKind::Unique,
                _ => IndexKind::Plain,
            };
            // A `STORING` column has no position: it is carried, not keyed.
            let keyed = optional_cell(&index_columns, row, "ordinal_position").is_some();
            let column = cell(row, "column_name")?;
            match indexes.iter_mut().find(|(existing, ..)| *existing == name) {
                Some((.., columns)) if keyed => columns.push(column),
                Some(_) => {}
                None => indexes.push((name, kind, keyed.then_some(column).into_iter().collect())),
            }
        }
        // Bare where they can be, as Spanner's own DDL writes them, which is
        // also how `Structure::row_key` reads the key back.
        let name = |name: &str| Engine::Spanner.quote_identifier_if_needed(name);
        let quoted = |columns: &[String]| {
            columns
                .iter()
                .map(|column| name(column))
                .collect::<Vec<_>>()
                .join(", ")
        };
        for (index, kind, columns) in indexes {
            let definition = match kind {
                IndexKind::Primary => format!("PRIMARY KEY ({})", quoted(&columns)),
                IndexKind::Unique => format!(
                    "CREATE UNIQUE INDEX {} ON {} ({})",
                    name(&index),
                    Engine::Spanner.qualified(schema, relation),
                    quoted(&columns)
                ),
                _ => format!(
                    "CREATE INDEX {} ON {} ({})",
                    name(&index),
                    Engine::Spanner.qualified(schema, relation),
                    quoted(&columns)
                ),
            };
            // The key is how `Structure::row_key` names a row.
            if kind == IndexKind::Primary {
                structure.constraints.push(NamedDefinition {
                    name: index.clone(),
                    definition: definition.clone(),
                });
            }
            structure.indexes.push(Index {
                name: index,
                kind,
                columns,
                predicate: None,
                definition,
            });
        }
        // One constraint per key, its columns in order.
        let mut keys: Vec<(String, Vec<&ForeignKey>)> = Vec::new();
        for (row, key) in foreign.rows.iter().zip(&structure.foreign_keys) {
            let constraint = required_cell(&foreign, row, "constraint_name")?.to_string();
            match keys
                .iter_mut()
                .find(|(existing, _)| *existing == constraint)
            {
                Some((_, columns)) => columns.push(key),
                None => keys.push((constraint, vec![key])),
            }
        }
        for (constraint, columns) in keys {
            let list = |pick: fn(&ForeignKey) -> &str| {
                columns
                    .iter()
                    .map(|key| name(pick(key)))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            structure.constraints.push(NamedDefinition {
                name: constraint,
                definition: format!(
                    "FOREIGN KEY ({}) REFERENCES {} ({})",
                    list(|key| &key.column),
                    Engine::Spanner
                        .qualified(&columns[0].referenced_schema, &columns[0].referenced_table),
                    list(|key| &key.referenced_column)
                ),
            });
        }
        Ok(structure)
    }

    /// Whether a read's rows can be written back, or why not. A result names
    /// no source table, so the statement has to read one table's own rows
    /// (`sql::table_read`), found in the catalog the way Spanner resolves a
    /// name, case-blind. A row is named by its primary key, and only where
    /// every key column takes a quoted literal: a bare number names no row
    /// the write gate admits.
    fn edit_target(&self, sql: &str, columns: &[Column]) -> (Option<EditTarget>, Option<String>) {
        let Some(read) = table_read(Engine::Spanner, sql) else {
            return (None, None);
        };
        let (schema, table) = match read.table.as_slice() {
            [table] => ("", table.as_str()),
            [schema, table] => (schema.as_str(), table.as_str()),
            _ => return (None, None),
        };
        let literal = |value: &str| Engine::Spanner.quote_literal(value);
        let lookup = |sql: String| self.internal_query(&sql).ok();
        let Some(found) = lookup(format!(
            "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES \
             WHERE TABLE_TYPE = 'BASE TABLE' AND LOWER(TABLE_SCHEMA) = LOWER({}) \
             AND LOWER(TABLE_NAME) = LOWER({})",
            literal(schema),
            literal(table)
        )) else {
            return (None, None);
        };
        let [row] = found.rows.as_slice() else {
            return (None, None);
        };
        let (Some(schema), Some(table)) = (row.get(0), row.get(1)) else {
            return (None, None);
        };
        let (schema, table) = (schema.to_string(), table.to_string());
        let within = format!(
            "TABLE_SCHEMA = {} AND TABLE_NAME = {}",
            literal(&schema),
            literal(&table)
        );
        let (Some(described), Some(keyed)) = (
            lookup(format!(
                "SELECT COLUMN_NAME, SPANNER_TYPE, IS_GENERATED FROM INFORMATION_SCHEMA.COLUMNS \
                 WHERE {within} ORDER BY ORDINAL_POSITION"
            )),
            lookup(format!(
                "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.INDEX_COLUMNS \
                 WHERE {within} AND INDEX_TYPE = 'PRIMARY_KEY' AND ORDINAL_POSITION IS NOT NULL \
                 ORDER BY ORDINAL_POSITION"
            )),
        ) else {
            return (None, None);
        };
        let cell = |row: &Row, at: usize| row.get(at).unwrap_or_default().to_string();
        let names: Vec<String> = described.rows.iter().map(|row| cell(row, 0)).collect();
        let origins: Vec<Option<String>> = read
            .columns
            .iter()
            .flat_map(|projected| match projected {
                Projected::Every => names.iter().cloned().map(Some).collect(),
                Projected::Column(written) => vec![
                    names
                        .iter()
                        .find(|name| name.eq_ignore_ascii_case(written))
                        .cloned(),
                ],
                Projected::Computed => vec![None],
            })
            .collect();
        // Read one way by the statement and another by the server.
        if origins.len() != columns.len() {
            return (None, None);
        }
        let mut seen = std::collections::HashSet::new();
        if !origins.iter().flatten().all(|origin| seen.insert(origin)) {
            return (None, None);
        }
        let type_of = |name: &str| {
            described
                .rows
                .iter()
                .find(|row| row.get(0) == Some(name))
                .map(|row| (cell(row, 1), row.get(2) == Some("ALWAYS")))
        };
        let key: Vec<String> = keyed.rows.iter().map(|row| cell(row, 0)).collect();
        let Some(keys) = key
            .iter()
            .map(|name| {
                origins
                    .iter()
                    .position(|origin| origin.as_ref() == Some(name))
            })
            .collect::<Option<Vec<usize>>>()
            .filter(|keys| !keys.is_empty())
        else {
            return (
                None,
                Some(format!(
                    "The rows cannot be written back: they are named by {}, which this \
                     statement does not read.",
                    key.join(", ")
                )),
            );
        };
        let unwritable: Vec<String> = key
            .iter()
            .filter_map(|name| {
                let (kind, _) = type_of(name)?;
                (!writable(&kind)).then(|| format!("{name} ({kind})"))
            })
            .collect();
        if !unwritable.is_empty() {
            return (
                None,
                Some(format!(
                    "The rows cannot be written back: their key, {}, has no literal DBDelve \
                     writes.",
                    unwritable.join(", ")
                )),
            );
        }
        // A column no literal the gate admits can set is read, not written.
        let columns = origins
            .into_iter()
            .map(|origin| {
                origin.filter(|name| {
                    type_of(name).is_some_and(|(kind, generated)| !generated && writable(&kind))
                })
            })
            .collect();
        (
            Some(EditTarget {
                schema,
                table,
                columns,
                keys,
                ..EditTarget::default()
            }),
            None,
        )
    }

    /// The relation's statements out of the database's own DDL, as the
    /// server keeps them: its `CREATE`, its indexes and any `ALTER`.
    pub fn ddl(&self, schema: &str, relation: &str) -> Result<String, DbError> {
        let run = Run::new(Bounds::internal());
        let _watching = run.watch.enter();
        let answer = self
            .json(
                "GET",
                &format!("{}/ddl", self.database),
                None,
                run.bounds,
                None,
            )
            .map_err(|refused| refused.error)?;
        let name = match schema {
            "" => relation.to_string(),
            schema => format!("{schema}.{relation}"),
        };
        let statements: Vec<String> = answer["statements"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|statement| {
                concerns(statement).is_some_and(|of| of.eq_ignore_ascii_case(&name))
            })
            .map(terminated)
            .collect();
        match statements.is_empty() {
            true => Err(plain_error(format!("{name} has no definition to show."))),
            false => Ok(statements.join("\n\n")),
        }
    }
}

/// The relation a DDL statement creates, indexes or alters, its parts
/// joined with `.` and unquoted: `CREATE TABLE s.t (…)`, `CREATE UNIQUE
/// INDEX i ON t (…)`, `ALTER TABLE t …`, `CREATE OR REPLACE VIEW v …`.
fn concerns(statement: &str) -> Option<String> {
    let tokens = Tokenizer::new(&BigQueryDialect {}, statement)
        .tokenize()
        .ok()?;
    let mut tokens = tokens
        .into_iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .peekable();
    let keyword = |token: &Token| match token {
        Token::Word(word) if word.quote_style.is_none() => word.value.to_ascii_uppercase(),
        _ => String::new(),
    };
    let first = keyword(&tokens.next()?);
    let mut index = false;
    while let Some(token) = tokens.next() {
        let word = keyword(&token);
        let named = match (first.as_str(), word.as_str()) {
            ("CREATE" | "ALTER", "TABLE" | "VIEW") => !index,
            ("CREATE", "ON") => index,
            _ => false,
        };
        index |= word == "INDEX";
        if !named {
            continue;
        }
        let mut parts = Vec::new();
        while let Some(Token::Word(part)) = tokens.peek() {
            if part.quote_style.is_none()
                && matches!(
                    part.value.to_ascii_uppercase().as_str(),
                    "IF" | "NOT" | "EXISTS"
                )
            {
                tokens.next();
                continue;
            }
            parts.push(part.value.clone());
            tokens.next();
            if tokens.peek() != Some(&Token::Period) {
                break;
            }
            tokens.next();
        }
        return Some(parts.join("."));
    }
    None
}

/// Whether GoogleSQL reads a quoted literal as a value of `kind`: it converts
/// a string literal to `DATE` and `TIMESTAMP` and nothing else.
/// Whether an edit can write a value of `kind`: quoted, or bare where
/// `typed_literal` spells one and the gate admits it (`bare_literals`).
fn writable(kind: &str) -> bool {
    ["STRING", "DATE", "TIMESTAMP"]
        .iter()
        .any(|name| kind == *name || kind.starts_with(&format!("{name}(")))
        || matches!(kind, "INT64" | "NUMERIC" | "FLOAT64" | "FLOAT32" | "BOOL")
}

/// Read first at connect: in either dialect, since unquoted names fold to
/// the view's in both.
const DIALECT_SQL: &str = "SELECT OPTION_VALUE FROM INFORMATION_SCHEMA.DATABASE_OPTIONS \
                           WHERE OPTION_NAME = 'database_dialect'";

/// The default schema's name is `''`, and its relations are written bare.
const RELATIONS_SQL: &str = "
SELECT
    TABLE_SCHEMA AS schema_name,
    TABLE_NAME AS relation_name,
    CASE TABLE_TYPE WHEN 'VIEW' THEN 'view' ELSE 'table' END AS relation_kind
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'SPANNER_SYS')
ORDER BY TABLE_SCHEMA, TABLE_NAME";

/// A generated and an identity column say so outside `COLUMN_DEFAULT`, so
/// they are spelled into the default's place the way the spec's markers
/// read them.
const COLUMNS_SQL: &str = "
SELECT
    COLUMN_NAME AS column_name,
    SPANNER_TYPE AS data_type,
    LOWER(IS_NULLABLE) AS nullable,
    CASE
        WHEN IS_GENERATED = 'ALWAYS' THEN
            CONCAT('AS (', GENERATION_EXPRESSION, ')', IF(IS_STORED = 'YES', ' STORED', ''))
        WHEN IS_IDENTITY = 'YES' THEN 'GENERATED BY DEFAULT AS IDENTITY'
        ELSE COALESCE(COLUMN_DEFAULT, '')
    END AS column_default
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = {schema} AND TABLE_NAME = {relation}
ORDER BY ORDINAL_POSITION";

/// One row per column of each index, gathered in Rust: Spanner's
/// `STRING_AGG` takes no `ORDER BY`. A `STORING` column has a NULL position
/// and sorts first.
const INDEX_COLUMNS_SQL: &str = "
SELECT
    c.INDEX_NAME AS index_name,
    c.INDEX_TYPE AS index_type,
    CAST(i.IS_UNIQUE AS STRING) AS is_unique,
    c.COLUMN_NAME AS column_name,
    c.ORDINAL_POSITION AS ordinal_position
FROM INFORMATION_SCHEMA.INDEX_COLUMNS AS c
JOIN INFORMATION_SCHEMA.INDEXES AS i
  ON i.TABLE_SCHEMA = c.TABLE_SCHEMA AND i.TABLE_NAME = c.TABLE_NAME
 AND i.INDEX_NAME = c.INDEX_NAME
WHERE c.TABLE_SCHEMA = {schema} AND c.TABLE_NAME = {relation}
ORDER BY c.INDEX_TYPE DESC, c.INDEX_NAME, c.ORDINAL_POSITION";

const FOREIGN_KEYS_SQL: &str = "
SELECT
    k.CONSTRAINT_NAME AS constraint_name,
    k.COLUMN_NAME AS column_name,
    u.TABLE_SCHEMA AS referenced_schema,
    u.TABLE_NAME AS referenced_table,
    u.COLUMN_NAME AS referenced_column
FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS AS r
JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS k
  ON k.CONSTRAINT_SCHEMA = r.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME = r.CONSTRAINT_NAME
JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS u
  ON u.CONSTRAINT_SCHEMA = r.UNIQUE_CONSTRAINT_SCHEMA
 AND u.CONSTRAINT_NAME = r.UNIQUE_CONSTRAINT_NAME
 AND u.ORDINAL_POSITION = k.POSITION_IN_UNIQUE_CONSTRAINT
WHERE k.TABLE_SCHEMA = {schema} AND k.TABLE_NAME = {relation}
ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_goes_out_bare_only_for_a_numeric_type_and_only_when_it_is_one() {
        assert_eq!(typed_literal("42", "INT64").as_deref(), Some("42"));
        assert_eq!(typed_literal("-7", "INT64").as_deref(), Some("-7"));
        assert_eq!(typed_literal("1.5", "NUMERIC").as_deref(), Some("1.5"));
        assert_eq!(typed_literal("-1e-3", "FLOAT64").as_deref(), Some("-1e-3"));
        assert_eq!(typed_literal("2.5", "FLOAT32").as_deref(), Some("2.5"));
        assert_eq!(typed_literal("true", "BOOL").as_deref(), Some("true"));
        // Past what INT64 holds, an expression, a sign the grammar reads as
        // an operator, and what no bare literal spells: quoted, and refused.
        for (value, data_type) in [
            ("9223372036854775808", "INT64"),
            ("1+1", "INT64"),
            ("+1", "INT64"),
            ("1.5", "INT64"),
            ("1e3", "NUMERIC"),
            ("NaN", "FLOAT64"),
            ("inf", "FLOAT64"),
            (".5", "FLOAT64"),
            ("TRUE", "BOOL"),
            ("42", "STRING(MAX)"),
            ("2026-11-15", "DATE"),
        ] {
            assert_eq!(
                typed_literal(value, data_type),
                None,
                "{value} as {data_type}"
            );
        }
    }
}

#[cfg(test)]
mod gate {
    use crate::db::Engine;
    use crate::sql::{delete_row, insert_row, is_generated_write_on};

    fn types(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, kind)| (name.to_string(), kind.to_string()))
            .collect()
    }

    /// The design's escape for a quote passes the write gate unloosened, in
    /// both arms that read a literal's shape.
    #[test]
    fn a_quote_written_as_x27_passes_the_write_gate() {
        let key = types(&[("name", "STRING(MAX)")]);
        let delete = delete_row(Engine::Spanner, "", "singers", &[("name", "it's")], &key)
            .expect("a string key names a row");
        assert_eq!(delete, r"DELETE FROM `singers` WHERE `name` = 'it\x27s'");
        assert!(is_generated_write_on(Engine::Spanner, &delete));
        let insert = insert_row(
            Engine::Spanner,
            "",
            "singers",
            &[("name", Some("it's"))],
            &key,
        )
        .expect("a string is quoted");
        assert!(is_generated_write_on(Engine::Spanner, &insert));
    }

    /// A bare number or `TRUE` names, inserts and sets a value on Spanner
    /// alone; anything that is not one plain literal is still refused.
    #[test]
    fn a_bare_literal_is_admitted_on_spanner_and_nothing_more() {
        let key = types(&[("id", "INT64"), ("name", "STRING(MAX)"), ("ok", "BOOL")]);
        let delete =
            delete_row(Engine::Spanner, "", "singers", &[("id", "-1")], &key).expect("written");
        assert_eq!(delete, "DELETE FROM `singers` WHERE `id` = -1");
        assert!(is_generated_write_on(Engine::Spanner, &delete));
        let insert = insert_row(
            Engine::Spanner,
            "",
            "singers",
            &[("id", Some("1")), ("name", Some("x")), ("ok", Some("true"))],
            &key,
        )
        .expect("written");
        assert!(is_generated_write_on(Engine::Spanner, &insert), "{insert}");
        for update in [
            "UPDATE `singers` SET `score` = 1.5 WHERE `id` = 1",
            "UPDATE `singers` SET `score` = -2.5e-3, `ok` = FALSE WHERE `id` = -7",
        ] {
            assert!(is_generated_write_on(Engine::Spanner, update), "{update}");
            assert!(!is_generated_write_on(Engine::MySql, update), "{update}");
        }
        for refused in [
            "UPDATE `singers` SET `score` = `score` + 1 WHERE `id` = 1",
            "UPDATE `singers` SET `score` = `id` WHERE `id` = 1",
            "UPDATE `singers` SET `score` = CAST('1' AS INT64) WHERE `id` = 1",
            "UPDATE `singers` SET `score` = 1. WHERE `id` = 1",
            "DELETE FROM `singers` WHERE `id` = 1 + 1",
        ] {
            assert!(
                !is_generated_write_on(Engine::Spanner, refused),
                "{refused}"
            );
        }
    }

    /// A filter compares a column with a value spelled as its type reads
    /// one, in the default schema, which has no name, and the preview it
    /// lands in passes the select gate.
    #[test]
    fn a_filter_spells_its_value_by_type_and_names_the_default_schema_bare() {
        use crate::explorer::preview_sql;
        use crate::filter::{Operator, filter_predicate};
        use crate::sql::{is_generated_select, paged};

        for (data_type, value, predicate) in [
            ("INT64", "42", "`id` = 42"),
            ("NUMERIC", "1.5", "`id` = 1.5"),
            ("BOOL", "true", "`id` = true"),
            ("DATE", "2026-11-15", "`id` = '2026-11-15'"),
            ("STRING(MAX)", "it's", r"`id` = 'it\x27s'"),
            // Not a number: quoted, and refused by the server in its words.
            ("INT64", "abc", "`id` = 'abc'"),
        ] {
            let filter = filter_predicate(
                Engine::Spanner,
                "id",
                Some(data_type),
                Operator::Equals,
                value,
            )
            .expect("an equality is offered");
            assert_eq!(filter, predicate);
            let preview = preview_sql(Engine::Spanner, "", "singers", &filter, Some(100), 0);
            assert!(
                preview.starts_with("SELECT * FROM `singers` WHERE"),
                "{preview}"
            );
            assert!(is_generated_select(Engine::Spanner, &preview), "{preview}");
        }

        let page = preview_sql(Engine::Spanner, "", "singers", "", Some(100), 200);
        let keyed = paged(Engine::Spanner, &page, &["id".to_string()]).expect("paged");
        assert_eq!(
            keyed,
            "SELECT * FROM `singers` ORDER BY `id` LIMIT 100 OFFSET 200"
        );
        assert!(is_generated_select(Engine::Spanner, &keyed));
    }
}

#[cfg(test)]
mod dialect {
    use crate::db::Engine;
    use crate::sql::{Buffer, Destructive, Mode, classify};

    fn split(sql: &str) -> Vec<&str> {
        Buffer::for_engine(Engine::Spanner, sql)
            .statements()
            .iter()
            .map(|range| &sql[range.clone()])
            .collect()
    }

    #[test]
    fn a_buffer_is_cut_where_googlesql_ends_a_statement() {
        for (sql, statements) in [
            (
                "FROM singers |> WHERE id > 1 |> SELECT name",
                &["FROM singers |> WHERE id > 1 |> SELECT name"][..],
            ),
            (
                "SELECT 1; FROM singers |> SELECT name; SELECT 2",
                &["SELECT 1", "FROM singers |> SELECT name", "SELECT 2"],
            ),
            (
                "SELECT * FROM singers |> WHERE id > 1; SELECT 2",
                &["SELECT * FROM singers |> WHERE id > 1", "SELECT 2"],
            ),
            (
                "INSERT INTO singers (id) VALUES (5) THEN RETURN id; SELECT 2",
                &[
                    "INSERT INTO singers (id) VALUES (5) THEN RETURN id",
                    "SELECT 2",
                ],
            ),
            (
                "@{OPTIMIZER_VERSION=7} SELECT 1; SELECT 2",
                &["@{OPTIMIZER_VERSION=7} SELECT 1", "SELECT 2"],
            ),
            // The grammar ends a string at `\'`, and reads `#` as an operator.
            (
                r"SELECT 'it\'s; x'; SELECT 2",
                &[r"SELECT 'it\'s; x'", "SELECT 2"],
            ),
            (
                "SELECT '''a; b'''; SELECT 2",
                &["SELECT '''a; b'''", "SELECT 2"],
            ),
            ("SELECT 1 # c; d\n; SELECT 2", &["SELECT 1", "SELECT 2"]),
        ] {
            assert_eq!(split(sql), statements, "{sql}");
        }
        // Mid-typing, the tokenizer gives up and the grammar still finds
        // the statement under the cursor.
        assert_eq!(
            split("SELECT 1; SELECT 'unclosed"),
            ["SELECT 1", "SELECT 'unclosed"]
        );
    }

    #[test]
    fn format_query_leads_each_pipe_operator_with_its_bar_and_refuses_what_it_would_change() {
        use crate::sql::format;
        assert_eq!(
            format(
                Engine::Spanner,
                "FROM singers |> WHERE id > 1 |> AGGREGATE COUNT(*) AS n GROUP BY name"
            )
            .as_deref(),
            Ok(
                "FROM\n  singers\n|> WHERE\n     id > 1\n|> AGGREGATE COUNT(*) AS n\n   GROUP BY\n     name"
            )
        );
        // A `|>` inside parentheses stays on the subquery's own line.
        assert!(
            format(
                Engine::Spanner,
                "SELECT * FROM (FROM t |> SELECT a) |> WHERE a > 1"
            )
            .is_ok_and(|laid| laid.matches("\n|> ").count() == 1)
        );
        // `sqlformat` would split these, and the guard refuses rather than
        // change what they say.
        for sql in [
            "SELECT '''a ' b'''",
            "SELECT r'a' AS t",
            "@{OPTIMIZER_VERSION=7} SELECT 1",
        ] {
            assert!(format(Engine::Spanner, sql).is_err(), "{sql}");
        }
    }

    #[test]
    fn pipe_queries_read_dml_writes_and_what_will_not_parse_runs_once() {
        for sql in [
            "FROM singers |> WHERE id > 1 |> SELECT name",
            "FROM singers |> AGGREGATE COUNT(*) GROUP BY name",
            "FROM singers |> DROP name",
            "FROM singers |> SET name = 'x'",
            "FROM singers |> EXTEND UPPER(name) AS up |> ORDER BY up |> LIMIT 5",
            "SELECT * FROM singers |> WHERE id > 1",
        ] {
            assert_eq!(
                classify(Engine::Spanner, sql),
                crate::sql::Verdict::READ,
                "{sql}"
            );
        }
        for sql in [
            "INSERT INTO singers (id) VALUES (5)",
            "UPDATE singers SET name = 'x' WHERE id = 1",
            "DELETE FROM singers WHERE id = 1",
            "DELETE FROM singers WHERE true",
        ] {
            assert_eq!(
                classify(Engine::Spanner, sql).mode,
                Mode::ReadWrite,
                "{sql}"
            );
        }
        assert_eq!(
            classify(Engine::Spanner, "DROP TABLE singers").destructive,
            [Destructive::Drop]
        );
        // The server holds Read-only on every request, so these run once,
        // asked, in any mode.
        for sql in [
            "FROM singers |> WINDOW COUNT(*) OVER () AS n",
            "INSERT INTO singers (id) VALUES (5) THEN RETURN id",
            "INSERT OR UPDATE INTO singers (id) VALUES (5)",
            "@{OPTIMIZER_VERSION=7} SELECT 1",
            "CREATE TABLE t (id INT64, s STRING(MAX)) PRIMARY KEY (id)",
            "CREATE TABLE c (id INT64, n INT64) PRIMARY KEY (id, n), INTERLEAVE IN PARENT t",
            "CREATE INDEX i ON t (s) STORING (n)",
            "CREATE CHANGE STREAM s FOR ALL",
        ] {
            let verdict = classify(Engine::Spanner, sql);
            assert_eq!(verdict.mode, Mode::ReadOnly, "{sql}");
            assert_eq!(verdict.destructive, [Destructive::Unreadable], "{sql}");
        }
    }
}

#[cfg(test)]
mod live {
    use super::*;

    const LIVE: &str =
        "requires the development emulator configured through dbdelve_SPANNER_EMULATOR";

    fn config() -> SpannerConfig {
        SpannerConfig {
            project: "dbdelve-dev".into(),
            instance: "dev".into(),
            database: "dbdelve_dev".into(),
            emulator: std::env::var("dbdelve_SPANNER_EMULATOR")
                .expect("dbdelve_SPANNER_EMULATOR is required"),
            ..SpannerConfig::default()
        }
    }

    fn live() -> Connection {
        Connection::open(&config()).expect("connection should open")
    }

    fn run(connection: &Connection, sql: &str) -> Result<QueryResult, DbError> {
        connection.query(sql, &CancelToken::default(), Fetch::default())
    }

    #[test]
    #[ignore = "requires the development emulator configured through dbdelve_SPANNER_EMULATOR"]
    fn live_a_read_renders_every_type_as_text() {
        let _ = LIVE;
        let result = run(
            &live(),
            "SELECT 1 AS i, 'it\\x27s' AS s, NUMERIC '1.5' AS n, 2.5 AS f, \
             CAST('NaN' AS FLOAT64) AS nan, true AS b, DATE '2026-11-15' AS d, \
             TIMESTAMP '2026-11-15T01:02:03Z' AS t, b'abc' AS raw, JSON '{\"a\":1}' AS j, \
             [1, 2] AS ints, ['a', NULL] AS strings, CAST(NULL AS STRING) AS nothing",
        )
        .expect("a read");
        let types: Vec<_> = result
            .columns
            .iter()
            .map(|column| column.data_type.clone().unwrap_or_default())
            .collect();
        assert_eq!(
            types,
            [
                "INT64",
                "STRING",
                "NUMERIC",
                "FLOAT64",
                "FLOAT64",
                "BOOL",
                "DATE",
                "TIMESTAMP",
                "BYTES",
                "JSON",
                "ARRAY<INT64>",
                "ARRAY<STRING>",
                "STRING"
            ]
        );
        let row: Vec<_> = result.rows[0].iter().collect();
        assert_eq!(
            row,
            [
                Some("1"),
                Some("it's"),
                Some("1.5"),
                Some("2.5"),
                Some("NaN"),
                Some("true"),
                Some("2026-11-15"),
                Some("2026-11-15T01:02:03Z"),
                Some("YWJj"),
                Some("{\"a\":1}"),
                Some("[1, 2]"),
                Some("[\"a\", null]"),
                None
            ]
        );
    }

    fn conformance_subject() -> crate::db::conformance::Subject {
        use crate::db::conformance::{COLUMNS, Fixture, Subject, sql_find, sql_read};
        Subject {
            connection: crate::db::Connection::open(crate::db::ConnectionConfig::Spanner(config()))
                .expect("connection should open"),
            target: crate::db::Target::built_in(Engine::Spanner),
            schema: "",
            relation: "conformance",
            key: "id",
            columns: &COLUMNS,
            read: sql_read(Engine::Spanner, ""),
            endless_rows: None,
            // The emulator builds a result whole before sending a row, and
            // `GENERATE_ARRAY` stops at 16 000 elements.
            endless: "SELECT x FROM UNNEST(GENERATE_ARRAY(1, 16000)) AS x",
            // It also runs a query on after its client hangs up, so this
            // one is slow without holding memory, and ends on its own.
            runaway: "SELECT COUNT(*) FROM UNNEST(GENERATE_ARRAY(1, 16000)) AS a \
                      CROSS JOIN UNNEST(GENERATE_ARRAY(1, 16000)) AS b",
            read_only_refusal: "single-use transactions",
            fixture: Some(Fixture {
                types: &[
                    "INT64",
                    "STRING",
                    "INT64",
                    "NUMERIC",
                    "FLOAT64",
                    "BOOL",
                    "DATE",
                    "TIMESTAMP",
                    "BYTES",
                ],
                renders: &[
                    ("fraction", 0, "12.5"),
                    ("flag", 0, "true"),
                    ("flag", 1, "false"),
                    ("moment", 0, "2024-02-29T12:34:56Z"),
                    ("moment", 1, "1999-12-31T23:59:59Z"),
                    // BYTES arrive as base64 and are shown as that.
                    ("bytes", 0, "AP8="),
                    ("bytes", 1, "3q2+7w=="),
                ],
                find: Box::new(|key| sql_find(Engine::Spanner, "", key)),
            }),
            _guard: None,
        }
    }

    // Not `capped_read_keeps_the_users_transaction`: there is no `BEGIN`.
    // Not `generated_writes_round_trip` or `generated_reads_run`: the
    // fixture is keyed by an `INT64`, whose rows DBDelve does not name, and
    // its neutral values compare a `BOOL` with `1`; Spanner's own versions
    // are below.
    crate::db::conformance::suite!(
        live_conformance,
        "requires the development emulator configured through dbdelve_SPANNER_EMULATOR",
        conformance_subject:
        connects,
        query_round_trip,
        catalog_round_trip,
        structure_round_trip,
        types_render_as_expected,
        cancel_stops_a_long_query,
        row_limit_stops_an_eligible_read,
        row_limit_drains_an_ineligible_read,
        read_only_session_refuses_a_write,
    );

    /// Every filter operator the bar offers, sorted and paged by key, as a
    /// preview of the seeded `conformance` table, with values as the grid
    /// shows them.
    #[test]
    #[ignore = "requires the development emulator configured through dbdelve_SPANNER_EMULATOR"]
    fn live_filters_sorts_and_pages_read_what_they_say() {
        use crate::explorer::{count_sql, preview_sql};
        use crate::filter::{Operator, filter_predicate};
        use crate::sql::{is_generated_select, paged};
        let connection = live();
        connection.set_read_only(true).expect("held");
        let structure = connection.structure("", "conformance").expect("structure");
        let type_of = |column: &str| {
            structure
                .columns
                .iter()
                .find(|candidate| candidate.name == column)
                .map(|candidate| candidate.data_type.clone())
        };
        let ids = |filter: &str| -> Vec<String> {
            let sql = paged(
                Engine::Spanner,
                &preview_sql(Engine::Spanner, "", "conformance", filter, Some(10), 0),
                &["id".to_string()],
            )
            .expect("paged");
            assert!(is_generated_select(Engine::Spanner, &sql), "{sql}");
            run(&connection, &sql)
                .unwrap_or_else(|error| panic!("{sql}: {error}"))
                .rows
                .iter()
                .map(|row| row.get(0).unwrap_or_default().to_string())
                .collect()
        };
        let predicate = |column: &str, operator: Operator, value: &str| {
            filter_predicate(
                Engine::Spanner,
                column,
                type_of(column).as_deref(),
                operator,
                value,
            )
            .expect("offered")
        };
        for (column, operator, value, wanted) in [
            ("label", Operator::Equals, "Zoë 李 🐉 'quoted'", &["2"][..]),
            ("label", Operator::NotEquals, "alpha", &["2", "3"]),
            ("label", Operator::Contains, "'quoted", &["2"]),
            ("label", Operator::NotContains, "lph", &["2", "3"]),
            ("label", Operator::StartsWith, "nul", &["3"]),
            ("label", Operator::EndsWith, "pha", &["1"]),
            ("id", Operator::Greater, "1", &["2", "3"]),
            ("id", Operator::LessOrEqual, "2", &["1", "2"]),
            ("whole", Operator::Equals, "9007199254740993", &["1"]),
            ("whole", Operator::IsNull, "", &["3"]),
            ("label", Operator::IsEmpty, "", &[]),
            ("id", Operator::InList, "1, 3", &["1", "3"]),
            ("id", Operator::Between, "1 .. 2", &["1", "2"]),
            ("label", Operator::Regex, "^al", &["1"]),
            ("fraction", Operator::Equals, "12.5", &["1"]),
            ("ratio", Operator::Equals, "-1.25", &["2"]),
            ("flag", Operator::Equals, "true", &["1"]),
            ("day", Operator::Equals, "1999-12-31", &["2"]),
            ("moment", Operator::Equals, "2024-02-29T12:34:56Z", &["1"]),
            ("moment", Operator::Contains, "1999", &["2"]),
            ("id", Operator::Contains, "2", &["2"]),
        ] {
            assert_eq!(
                ids(&predicate(column, operator, value)),
                wanted,
                "{column} {operator:?} {value}"
            );
        }
        let page = paged(
            Engine::Spanner,
            &preview_sql(Engine::Spanner, "", "conformance", "", Some(1), 1),
            &["id".to_string()],
        )
        .expect("paged");
        assert_eq!(
            run(&connection, &page).expect("a page").rows[0].get(0),
            Some("2")
        );
        let sorted = crate::sql::with_order_by(
            Engine::Spanner,
            &preview_sql(Engine::Spanner, "", "conformance", "", Some(10), 0),
            &[crate::sql::SortKey {
                expression: "`label`".into(),
                ascending: false,
            }],
        )
        .expect("spliced");
        assert!(is_generated_select(Engine::Spanner, &sorted), "{sorted}");
        let first = run(&connection, &sorted).expect("sorted");
        // Byte order: `n` sorts after `Z`.
        assert_eq!(first.rows[0].get(1), Some("nulls"), "{sorted}");
        let count = count_sql(Engine::Spanner, "", "conformance", "");
        assert_eq!(
            run(&connection, &count).expect("a count").rows[0].get(0),
            Some("3")
        );
    }

    /// The writes stage 3 is done by: an edit, an insert, a row delete, a
    /// multi-row edit that fails half way and a schema change, each as the
    /// grid or the user would send it, through the gate first.
    #[test]
    #[ignore = "requires the development emulator configured through dbdelve_SPANNER_EMULATOR"]
    fn live_edits_inserts_deletes_and_schema_changes_do_what_they_say() {
        use crate::sql::{delete_row, insert_row, is_generated_write_on};
        let connection = live();
        let types: Vec<(String, String)> = [
            ("name", "STRING(64)"),
            ("note", "STRING(MAX)"),
            ("rank", "INT64"),
        ]
        .iter()
        .map(|(name, kind)| (name.to_string(), kind.to_string()))
        .collect();
        let gated = |sql: &str| {
            assert!(
                is_generated_write_on(Engine::Spanner, sql),
                "the gate refuses {sql}"
            );
            run(&connection, sql).unwrap_or_else(|error| panic!("{sql}: {error}"))
        };
        let note = |name: &str| {
            run(
                &connection,
                &format!(
                    "SELECT note FROM labels WHERE name = {}",
                    Engine::Spanner.quote_literal(name)
                ),
            )
            .expect("read")
            .rows
            .first()
            .map(|row| row.get(0).map(str::to_string))
        };
        let preview = run(&connection, "SELECT * FROM labels").expect("preview");
        assert_eq!(preview.edit.expect("keyed by a string").keys, [0]);
        let singers = run(&connection, "SELECT * FROM singers").expect("preview");
        assert_eq!(singers.edit.expect("keyed by a number").keys, [0]);

        // A row keyed by an INT64, every numeric type and BOOL written bare.
        let numbers: Vec<(String, String)> = [
            ("id", "INT64"),
            ("name", "STRING(MAX)"),
            ("score", "NUMERIC"),
            ("ok", "BOOL"),
            ("f", "FLOAT64"),
        ]
        .iter()
        .map(|(name, kind)| (name.to_string(), kind.to_string()))
        .collect();
        let id = [("id", "-9001")];
        gated(
            &insert_row(
                Engine::Spanner,
                "",
                "singers",
                &[
                    ("id", Some("-9001")),
                    ("name", Some("numbered")),
                    ("score", Some("1.25")),
                    ("ok", Some("true")),
                    ("f", Some("-2.5e-3")),
                ],
                &numbers,
            )
            .expect("insertable"),
        );
        let update = crate::sql::update_row(
            Engine::Spanner,
            "",
            "singers",
            &[
                ("score", crate::result_grid::NewValue::Value("-7.5".into())),
                ("ok", crate::result_grid::NewValue::Value("false".into())),
                ("f", crate::result_grid::NewValue::Value("3".into())),
            ],
            &id,
            &numbers,
        )
        .expect("an update");
        assert_eq!(gated(&update).rows_affected, Some(1));
        let row = run(
            &connection,
            "SELECT CAST(score AS STRING), ok, f FROM singers WHERE id = -9001",
        )
        .expect("read");
        assert_eq!(
            (0..3)
                .map(|at| row.rows[0].get(at).map(str::to_string))
                .collect::<Vec<_>>(),
            [Some("-7.5".into()), Some("false".into()), Some("3".into())]
        );
        let delete = delete_row(Engine::Spanner, "", "singers", &id, &numbers).expect("a key");
        assert_eq!(gated(&delete).rows_affected, Some(1));

        // A quote and a line break in the key, both escaped in the literal.
        let key = "zz it's".to_string() + "\n" + "new";
        let lit = |value: &str| Engine::Spanner.quote_literal(value);
        let insert = insert_row(
            Engine::Spanner,
            "",
            "labels",
            &[("name", Some(key.as_str())), ("note", Some("inserted"))],
            &types,
        )
        .expect("insertable");
        gated(&insert);
        assert_eq!(note(&key), Some(Some("inserted".into())));

        let edit = format!(
            "UPDATE `labels` SET `note` = {}, `rank` = 7 WHERE `name` = {}",
            lit("edited '"),
            lit(&key)
        );
        assert_eq!(gated(&edit).rows_affected, Some(1));
        assert_eq!(note(&key), Some(Some("edited '".into())));

        // The second fails on its type, so the first is not applied either.
        let half = format!(
            "UPDATE `labels` SET `note` = 'half' WHERE `name` = 'alpha';\n\
             UPDATE `labels` SET `note` = 'half' WHERE `name` = {} AND `rank` = 'x'",
            lit(&key)
        );
        assert!(is_generated_write_on(Engine::Spanner, &half));
        let error = run(&connection, &half).expect_err("refused");
        assert!(
            error.message.starts_with("Statement 2 of 2 failed"),
            "{}",
            error.message
        );
        assert_eq!(note("alpha"), Some(Some("first".into())));

        let delete = delete_row(
            Engine::Spanner,
            "",
            "labels",
            &[("name", key.as_str())],
            &types,
        )
        .expect("a string key");
        assert_eq!(gated(&delete).rows_affected, Some(1));
        assert_eq!(note(&key), None);

        run(
            &connection,
            "CREATE TABLE live_made (id STRING(10) NOT NULL) PRIMARY KEY (id);",
        )
        .expect("created");
        assert!(
            connection.catalog().expect("catalog").schemas[0]
                .relations
                .iter()
                .any(|relation| relation.name == "live_made")
        );
        run(&connection, "DROP TABLE live_made").expect("dropped");
    }

    #[test]
    #[ignore = "requires the development emulator configured through dbdelve_SPANNER_EMULATOR"]
    fn live_the_catalog_and_a_structure_are_read() {
        let connection = live();
        let catalog = connection.catalog().expect("a catalog");
        eprintln!("{catalog:#?}");
        let structure = connection.structure("", "albums").expect("a structure");
        eprintln!("{structure:#?}");
        eprintln!("{:#?}", connection.databases().expect("databases"));
        eprintln!("{}", connection.ddl("", "albums").expect("ddl"));
        assert!(structure.row_key() == ["id", "album_id"]);
    }
}

#[cfg(test)]
mod offline {
    use super::auth::{Credential, from_json, self_signed};
    use super::mock::{DATABASE, Framing, Mock, Response, metadata};
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::KeyPair;

    fn service_account() -> String {
        let pem = std::fs::read_to_string(format!(
            "{}/dev/snowflake/test-key-2048.p8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("the test key");
        json!({
            "type": "service_account",
            "client_email": "reader@p.iam.gserviceaccount.com",
            "private_key_id": "k1",
            "private_key": pem,
        })
        .to_string()
    }

    fn open(mock: &Mock, credential: Credential) -> Connection {
        Connection::open_at(&mock.config(), &mock.base(), credential).expect("opened")
    }

    fn emulated(mock: &Mock) -> Connection {
        open(mock, Credential::Emulator)
    }

    fn run(connection: &Connection, sql: &str) -> Result<QueryResult, DbError> {
        connection.query(sql, &CancelToken::default(), Fetch::default())
    }

    fn rows(result: &QueryResult) -> Vec<Vec<Option<&str>>> {
        result.rows.iter().map(|row| row.iter().collect()).collect()
    }

    fn reads(mock: &Mock, framing: Framing, sql: &str, messages: &[Value]) {
        mock.on(
            "POST",
            ":executeStreamingSql",
            sql,
            [Response::stream(framing, messages)],
        );
    }

    #[test]
    fn a_service_accounts_token_is_signed_for_spanner_and_names_its_key() {
        let Credential::ServiceAccount { email, key_id, key } =
            from_json(&service_account(), "key.json", false).expect("a service account")
        else {
            panic!("not a service account");
        };
        let token = self_signed(&email, &key_id, &key, 1_000).expect("signed");
        let parts: Vec<_> = token.split('.').collect();
        let decode = |part: &str| -> Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
        };
        assert_eq!(
            decode(parts[0]),
            json!({"alg": "RS256", "typ": "JWT", "kid": "k1"})
        );
        assert_eq!(
            decode(parts[1]),
            json!({
                "iss": "reader@p.iam.gserviceaccount.com",
                "sub": "reader@p.iam.gserviceaccount.com",
                "aud": "https://spanner.googleapis.com/",
                "iat": 1_000,
                "exp": 4_600,
            })
        );
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key.public_key().as_ref(),
        )
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).expect("base64url"),
        )
        .expect("signed over the header and claims");
    }

    #[test]
    fn a_credential_dbdelve_does_not_sign_in_with_is_refused_by_name() {
        let refused = |text: &str, default: bool| {
            from_json(text, "/c.json", default)
                .expect_err("refused")
                .message
        };
        assert!(
            refused(r#"{"type": "external_account"}"#, true).contains("of type external_account")
        );
        // A user's sign-in is never a key file the form names.
        let user = r#"{"type": "authorized_user", "client_id": "a", "client_secret": "b",
                       "refresh_token": "c"}"#;
        assert!(refused(user, false).contains("of type authorized_user"));
        assert!(from_json(user, "/c.json", true).is_ok());
        assert!(refused("{}", true).contains("name no type"));
        assert!(refused("not json", true).contains("are not JSON"));
        assert!(
            refused(r#"{"type": "service_account", "private_key": "x"}"#, false)
                .contains("no RSA private key")
        );
    }

    #[test]
    fn a_service_account_signs_every_request_and_the_emulator_none() {
        let mock = Mock::start();
        let credential = from_json(&service_account(), "key.json", false).expect("read");
        open(&mock, credential);
        let signed = mock.sent("/sessions");
        let bearer = signed[0].header("authorization").expect("a token");
        assert!(bearer.starts_with("Bearer ey"), "{bearer}");
        assert!(
            mock.sent(":executeStreamingSql")[0]
                .header("authorization")
                .is_some()
        );

        let mock = Mock::start();
        emulated(&mock);
        assert!(
            mock.requests()
                .iter()
                .all(|request| request.header("authorization").is_none())
        );
    }

    #[test]
    fn a_users_refresh_token_is_exchanged_once_and_bills_their_project() {
        let mock = Mock::start();
        mock.on(
            "POST",
            "/token",
            "",
            [Response::json(
                200,
                json!({"access_token": "ya29.t", "expires_in": 3599}),
            )],
        );
        let credential = Credential::User {
            token_uri: format!("{}/token", mock.address),
            client_id: "id".into(),
            client_secret: "secret".into(),
            refresh_token: "refresh".into(),
            quota_project: Some("billing".into()),
        };
        let connection = open(&mock, credential);
        run(&connection, "SELECT 1").ok();
        let exchanges = mock.sent("/token");
        assert_eq!(exchanges.len(), 1, "cached for the next request");
        assert!(exchanges[0].raw.contains("grant_type=refresh_token"));
        assert!(exchanges[0].raw.contains("refresh_token=refresh"));
        let session = &mock.sent("/sessions")[0];
        assert_eq!(session.header("authorization"), Some("Bearer ya29.t"));
        assert_eq!(session.header("x-goog-user-project"), Some("billing"));
    }

    #[test]
    fn a_refused_refresh_token_says_so_in_the_endpoints_words() {
        let mock = Mock::start();
        mock.on(
            "POST",
            "/token",
            "",
            [Response::json(
                400,
                json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}),
            )],
        );
        let credential = Credential::User {
            token_uri: format!("{}/token", mock.address),
            client_id: "id".into(),
            client_secret: "secret".into(),
            refresh_token: "refresh".into(),
            quota_project: None,
        };
        let error = Connection::open_at(&mock.config(), &mock.base(), credential)
            .err()
            .expect("refused");
        assert_eq!(
            error.message,
            "The application default credentials were refused: Token has been expired or revoked."
        );
    }

    #[test]
    fn a_postgresql_dialect_database_is_refused_at_connect() {
        let mock = Mock::start();
        mock.dialect("POSTGRESQL");
        let error = Connection::open_at(&mock.config(), &mock.base(), Credential::Emulator)
            .err()
            .expect("refused");
        assert!(
            error.message.contains("PostgreSQL-dialect"),
            "{}",
            error.message
        );
    }

    #[test]
    fn either_framing_of_a_stream_gives_the_same_rows_with_split_values_merged() {
        for framing in [Framing::Array, Framing::Lines] {
            let mock = Mock::start();
            reads(
                &mock,
                framing,
                "FROM t",
                &[
                    json!({
                        "metadata": {"rowType": {"fields": [
                            {"name": "s", "type": {"code": "STRING"}},
                            {"name": "a", "type": {"code": "ARRAY", "arrayElementType": {"code": "STRING"}}},
                        ]}},
                        "values": ["Hello", ["a", "b"], "W"],
                        "chunkedValue": true,
                    }),
                    json!({"values": ["orl"], "chunkedValue": true}),
                    json!({"values": ["d", ["c"]], "chunkedValue": true}),
                    json!({"values": [["d", "e"]]}),
                ],
            );
            let result = run(&emulated(&mock), "SELECT s, a FROM t").expect("read");
            assert_eq!(
                rows(&result),
                [
                    [Some("Hello"), Some(r#"["a", "b"]"#)],
                    [Some("World"), Some(r#"["cd", "e"]"#)]
                ],
                "{framing:?}"
            );
        }
    }

    #[test]
    fn chunks_merge_by_the_references_rules() {
        assert_eq!(merged(json!("foo"), json!("bar")), json!("foobar"));
        assert_eq!(merged(json!([2, 3]), json!([4])), json!([2, 3, 4]));
        assert_eq!(
            merged(json!(["a", "b"]), json!(["c", "d"])),
            json!(["a", "bc", "d"])
        );
        assert_eq!(
            merged(json!(["a", ["b", "c"]]), json!([["d"], "e"])),
            json!(["a", ["b", "cd"], "e"])
        );
        assert_eq!(
            merged(json!({"a": "1"}), json!({"b": "2"})),
            json!({"a": "1", "b": "2"})
        );
        assert_eq!(
            merged(json!({"a": ["1"]}), json!({"a": ["2"]})),
            json!({"a": ["12"]})
        );
    }

    #[test]
    fn nested_values_are_written_out_by_their_types() {
        let kind = json!({"code": "ARRAY", "arrayElementType": {"code": "STRUCT", "structType": {"fields": [
            {"name": "n", "type": {"code": "INT64"}},
            {"name": "s", "type": {"code": "STRING"}},
            {"name": "", "type": {"code": "BOOL"}},
        ]}}});
        assert_eq!(type_name(&kind), "ARRAY<STRUCT<n INT64, s STRING, BOOL>>");
        assert_eq!(
            render(&json!([["1", "x\"y", true], null]), &kind).as_deref(),
            Some(r#"[{"n": 1, "s": "x\"y", "_3": true}, null]"#)
        );
        assert_eq!(
            render(&json!("NaN"), &json!({"code": "FLOAT64"})).as_deref(),
            Some("NaN")
        );
        assert_eq!(render(&Value::Null, &json!({"code": "STRING"})), None);
    }

    #[test]
    fn the_statement_goes_out_as_typed_in_a_read_only_transaction() {
        let mock = Mock::start();
        let sql = "SELECT 'it\\x27s' -- note\nFROM t";
        reads(
            &mock,
            Framing::Array,
            "FROM t",
            &[metadata(&[("x", "STRING")])],
        );
        run(&emulated(&mock), sql).expect("read");
        let sent = mock
            .sent(":executeStreamingSql")
            .into_iter()
            .find(|request| request.body["sql"] == sql)
            .expect("sent as typed");
        assert_eq!(
            sent.body["transaction"],
            json!({"singleUse": {"readOnly": {"strong": true}}})
        );
        assert_eq!(
            sent.target,
            format!("{DATABASE}/sessions/reads:executeStreamingSql")
        );
    }

    #[test]
    fn the_services_error_body_is_shown_in_its_words_at_its_position() {
        let mock = Mock::start();
        mock.on(
            "POST",
            ":executeStreamingSql",
            "nope",
            [Response::json(
                400,
                json!({"error": {"code": 400, "status": "INVALID_ARGUMENT",
                    "message": "Table not found: nope [at 2:6]"}}),
            )],
        );
        let error = run(&emulated(&mock), "SELECT *\nFROM nope").expect_err("refused");
        assert_eq!(error.message, "Table not found: nope [at 2:6]");
        assert_eq!(error.position, Some("SELECT *\nFROM ".len()));
    }

    #[test]
    fn an_error_part_way_through_a_stream_ends_it_in_the_servers_words() {
        for framing in [Framing::Array, Framing::Lines] {
            let mock = Mock::start();
            let failing = match framing {
                Framing::Array => format!(
                    "[{},\n{}]",
                    metadata(&[("x", "INT64")]),
                    json!({"error": {"code": 400, "status": "OUT_OF_RANGE", "message": "Division by zero"}})
                ),
                Framing::Lines => format!(
                    "{}\n{}\n",
                    json!({"result": metadata(&[("x", "INT64")])}),
                    json!({"error": {"code": 11, "message": "Division by zero"}})
                ),
            };
            mock.on(
                "POST",
                ":executeStreamingSql",
                "1/0",
                [Response::text(200, &failing)],
            );
            let error = run(&emulated(&mock), "SELECT 1/0").expect_err("refused");
            assert_eq!(error.message, "Division by zero", "{framing:?}");
        }
    }

    #[test]
    fn an_empty_refusal_says_the_server_said_nothing_more() {
        let mock = Mock::start();
        mock.on(
            "POST",
            ":executeStreamingSql",
            "nope",
            [Response::text(400, "")],
        );
        let error = run(&emulated(&mock), "SELECT nope").expect_err("refused");
        assert_eq!(
            error.message,
            "Spanner answered HTTP 400 and said nothing more about why."
        );
    }

    #[test]
    fn a_stream_cut_short_is_an_error_and_not_fewer_rows() {
        let mock = Mock::start();
        mock.on(
            "POST",
            ":executeStreamingSql",
            "FROM t",
            [Response::text(
                200,
                &format!("[{},\n{{\"values\": [\"1\"", metadata(&[("x", "INT64")])),
            )],
        );
        let error = run(&emulated(&mock), "SELECT x FROM t").expect_err("cut");
        assert!(error.message.contains("cut off"), "{}", error.message);
    }

    fn numbers(count: usize) -> Vec<Value> {
        let mut messages = vec![metadata(&[("n", "INT64")])];
        messages.extend((0..count).map(|n| json!({"values": [n.to_string()]})));
        messages
    }

    #[test]
    fn a_read_past_the_row_limit_is_stopped_there() {
        let mock = Mock::start();
        reads(&mock, Framing::Lines, "FROM t", &numbers(10));
        let fetch = Fetch {
            limit: Some(3),
            reads_only: true,
            ..Fetch::default()
        };
        let result = emulated(&mock)
            .query("SELECT n FROM t", &CancelToken::default(), fetch)
            .expect("read");
        assert_eq!(result.rows.len(), 3);
        assert_eq!(result.stopped, Some(Stopped::AtLimit));
        assert_eq!(result.capped_from, None);
    }

    #[test]
    fn a_cancel_ends_a_read_that_is_still_arriving() {
        let mock = Mock::start();
        let body = Response::stream(Framing::Array, &numbers(2));
        mock.on(
            "POST",
            ":executeStreamingSql",
            "FROM slow",
            [body.stalled(20, Duration::from_secs(5))],
        );
        let connection = emulated(&mock);
        let cancel = CancelToken::default();
        let started = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                connection.cancel(&cancel).expect("asked");
            });
            let error = connection
                .query("SELECT n FROM slow", &cancel, Fetch::default())
                .expect_err("cancelled");
            assert_eq!(error.message, CANCELLED);
        });
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(crate::db::is_cancel(
            crate::db::Target::built_in(Engine::Spanner),
            &DbError {
                message: CANCELLED.into(),
                position: None
            }
        ));
    }

    #[test]
    fn a_response_that_goes_quiet_past_the_timeout_is_stopped() {
        let mock = Mock::start();
        let body = Response::stream(Framing::Array, &numbers(2));
        mock.on(
            "POST",
            ":executeStreamingSql",
            "FROM slow",
            [body.stalled(20, Duration::from_secs(5))],
        );
        let config = SpannerConfig {
            statement_timeout: 1,
            ..mock.config()
        };
        let connection =
            Connection::open_at(&config, &mock.base(), Credential::Emulator).expect("opened");
        let error = run(&connection, "SELECT n FROM slow").expect_err("stopped");
        assert!(
            error.message.starts_with("Spanner sent nothing for"),
            "{}",
            error.message
        );
    }

    #[test]
    fn read_only_sends_every_statement_as_a_read_and_never_reaches_the_ddl_endpoint() {
        let mock = Mock::start();
        mock.on(
            "POST",
            ":executeStreamingSql",
            "DELETE",
            [Response::json(
                400,
                json!({"error": {"code": 400, "status": "FAILED_PRECONDITION",
                    "message": "DML statements may not be performed in single-use transactions, to avoid replay."}}),
            )],
        );
        let connection = emulated(&mock);
        connection.set_read_only(true).expect("held");
        let error = run(&connection, "DELETE FROM t WHERE true").expect_err("refused");
        assert!(
            error.message.starts_with("DML statements may not"),
            "{}",
            error.message
        );
        let sent = mock.sent(":executeStreamingSql").pop().expect("sent");
        assert_eq!(
            sent.body["transaction"],
            json!({"singleUse": {"readOnly": {"strong": true}}})
        );

        let error = run(&connection, "/* x */ DROP TABLE t").expect_err("refused");
        assert!(
            error.message.starts_with("Read-only keeps"),
            "{}",
            error.message
        );
        assert!(mock.sent("/ddl").is_empty());
        assert!(mock.sent(":commit").is_empty());
        assert!(mock.sent(":executeBatchDml").is_empty());
    }

    fn writable(mock: &Mock) {
        mock.on(
            "POST",
            ":executeStreamingSql",
            "UPDATE",
            [Response::stream(
                Framing::Array,
                &[
                    json!({"metadata": {"rowType": {}, "transaction": {"id": "dHg="}},
                         "stats": {"rowCountExact": "1"}}),
                ],
            )],
        );
        mock.on(
            "POST",
            ":commit",
            "",
            [Response::json(200, json!({"commitTimestamp": "t"}))],
        );
        mock.on("POST", ":rollback", "", [Response::json(200, json!({}))]);
    }

    #[test]
    fn a_write_runs_in_a_read_write_transaction_on_its_own_session_and_commits() {
        let mock = Mock::start();
        writable(&mock);
        let result = run(&emulated(&mock), "UPDATE t SET a = 'x' WHERE k = 'y';").expect("written");
        assert_eq!(result.rows_affected, Some(1));
        let sent = mock.sent(":executeStreamingSql").pop().expect("sent");
        assert_eq!(
            sent.target,
            format!("{DATABASE}/sessions/writes:executeStreamingSql")
        );
        // The separator off, the statement otherwise as typed.
        assert_eq!(sent.body["sql"], "UPDATE t SET a = 'x' WHERE k = 'y'");
        assert_eq!(
            sent.body["transaction"],
            json!({"begin": {"readWrite": {}}})
        );
        assert_eq!(sent.body["seqno"], "1");
        assert_eq!(
            mock.sent(":commit")[0].body,
            json!({"transactionId": "dHg="})
        );
    }

    #[test]
    fn an_aborted_write_is_run_again_whole() {
        let mock = Mock::start();
        writable(&mock);
        mock.on(
            "POST",
            ":commit",
            "",
            [
                Response::json(409, json!({"error": {"code": 409, "status": "ABORTED", "message": "Transaction was aborted."}})),
                Response::json(200, json!({"commitTimestamp": "t"})),
            ],
        );
        run(&emulated(&mock), "UPDATE t SET a = 'x' WHERE k = 'y'").expect("written");
        assert_eq!(
            mock.sent(":executeStreamingSql").len(),
            3,
            "the dialect read and two tries"
        );
        assert_eq!(mock.sent(":commit").len(), 2);
    }

    #[test]
    fn several_writes_are_one_batch_applied_whole_or_rolled_back() {
        let mock = Mock::start();
        writable(&mock);
        mock.on(
            "POST",
            ":executeBatchDml",
            "",
            [Response::json(
                200,
                json!({"resultSets": [
                {"metadata": {"transaction": {"id": "YmF0Y2g="}}, "stats": {"rowCountExact": "1"}},
                {"stats": {"rowCountExact": "2"}},
            ], "status": {}}),
            )],
        );
        let edits = "UPDATE t SET a = 'x' WHERE k = '1';\nUPDATE t SET a = 'y' WHERE k = '2'";
        let result = run(&emulated(&mock), edits).expect("written");
        assert_eq!(result.rows_affected, Some(3));
        let batch = &mock.sent(":executeBatchDml")[0];
        assert_eq!(
            batch.body["statements"],
            json!([{"sql": "UPDATE t SET a = 'x' WHERE k = '1'"}, {"sql": "UPDATE t SET a = 'y' WHERE k = '2'"}])
        );
        assert_eq!(
            mock.sent(":commit")[0].body,
            json!({"transactionId": "YmF0Y2g="})
        );

        mock.on(
            "POST",
            ":executeBatchDml",
            "",
            [Response::json(
                200,
                json!({"resultSets": [
                {"metadata": {"transaction": {"id": "YmFk"}}, "stats": {"rowCountExact": "1"}},
            ], "status": {"code": 6, "message": "Row [2] already exists"}}),
            )],
        );
        let error = run(&emulated(&mock), edits).expect_err("refused");
        assert_eq!(
            error.message,
            "Statement 2 of 2 failed, and none of the batch was applied: Row [2] already exists"
        );
        assert_eq!(
            mock.sent(":rollback")[0].body,
            json!({"transactionId": "YmFk"})
        );
        assert_eq!(
            mock.sent(":commit").len(),
            1,
            "only the first batch committed"
        );
    }

    #[test]
    fn a_submission_mixing_kinds_is_refused_unsent() {
        let mock = Mock::start();
        let error =
            run(&emulated(&mock), "SELECT 1; UPDATE t SET a = 1 WHERE true").expect_err("refused");
        assert!(error.message.contains("mixing"), "{}", error.message);
        assert_eq!(
            mock.sent(":executeStreamingSql").len(),
            1,
            "only the connect's read"
        );
    }

    #[test]
    fn a_schema_change_is_an_operation_waited_on_until_done() {
        let mock = Mock::start();
        let operation = format!("{DATABASE}/operations/o1");
        mock.on(
            "PATCH",
            "/ddl",
            "",
            [Response::json(
                200,
                json!({"name": operation, "done": false}),
            )],
        );
        mock.on(
            "GET",
            "/operations/o1",
            "",
            [
                Response::json(200, json!({"name": operation})),
                Response::json(
                    200,
                    json!({"name": operation, "done": true, "response": {}}),
                ),
            ],
        );
        run(
            &emulated(&mock),
            "CREATE TABLE a (id INT64) PRIMARY KEY (id);\nCREATE INDEX i ON a (id);",
        )
        .expect("changed");
        assert_eq!(
            mock.sent("/ddl")[0].body,
            json!({"statements": ["CREATE TABLE a (id INT64) PRIMARY KEY (id)", "CREATE INDEX i ON a (id)"]})
        );
        assert_eq!(mock.sent("/operations/o1").len(), 2);

        mock.on(
            "GET",
            "/operations/o1",
            "",
            [Response::json(
                200,
                json!({"name": operation, "done": true,
                "error": {"code": 6, "message": "Duplicate name in schema: a."}}),
            )],
        );
        let error = run(
            &emulated(&mock),
            "CREATE TABLE a (id INT64) PRIMARY KEY (id)",
        )
        .expect_err("refused");
        assert_eq!(error.message, "Duplicate name in schema: a.");
    }

    #[test]
    fn a_cancelled_schema_change_asks_the_operation_to_stop() {
        let mock = Mock::start();
        let operation = format!("{DATABASE}/operations/o2");
        mock.on(
            "PATCH",
            "/ddl",
            "",
            [Response::json(200, json!({"name": operation}))],
        );
        mock.on(
            "GET",
            "/operations/o2",
            "",
            [Response::json(200, json!({"name": operation}))],
        );
        mock.on(
            "POST",
            "/operations/o2:cancel",
            "",
            [Response::json(200, json!({}))],
        );
        let connection = emulated(&mock);
        let cancel = CancelToken::default();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                connection.cancel(&cancel).expect("asked");
            });
            let error = connection
                .query(
                    "ALTER TABLE a ADD COLUMN b INT64",
                    &cancel,
                    Fetch::default(),
                )
                .expect_err("cancelled");
            assert!(error.message.starts_with(CANCELLED), "{}", error.message);
        });
        assert_eq!(mock.sent("/operations/o2:cancel").len(), 1);
    }

    #[test]
    fn a_statement_goes_to_the_api_its_first_keyword_names() {
        for (sql, expected) in [
            ("SELECT 1", Route::Read),
            ("FROM t |> SELECT a", Route::Read),
            ("WITH x AS (SELECT 1) SELECT * FROM x", Route::Read),
            ("-- c\n/* d */ insert into t (a) values (1)", Route::Write),
            (
                "@{PDML_MAX_PARALLELISM=1} UPDATE t SET a = 1 WHERE true",
                Route::Write,
            ),
            ("DELETE FROM t WHERE true", Route::Write),
            ("create table t (a INT64) primary key (a)", Route::Ddl),
            ("ALTER TABLE t ADD COLUMN b INT64", Route::Ddl),
            ("DROP TABLE t", Route::Ddl),
            ("GRANT SELECT ON TABLE t TO ROLE r", Route::Ddl),
            ("ANALYZE", Route::Ddl),
            ("SELECT 'unclosed", Route::Read),
        ] {
            assert_eq!(route(sql), expected, "{sql}");
        }
    }

    #[test]
    fn copy_ddl_takes_the_relations_own_statements_from_the_database() {
        let mock = Mock::start();
        mock.on(
            "GET",
            "/ddl",
            "",
            [Response::json(200, json!({"statements": [
                "CREATE TABLE singers (\n  id INT64 NOT NULL,\n) PRIMARY KEY(id)",
                "CREATE TABLE albums (\n  id INT64 NOT NULL,\n) PRIMARY KEY(id)",
                "CREATE UNIQUE INDEX albums_by_title ON albums(title) STORING (note)",
                "CREATE INDEX singers_by_name ON singers(name)",
                "ALTER TABLE albums ADD CONSTRAINT fk FOREIGN KEY (id) REFERENCES singers (id)",
                "CREATE VIEW singer_names SQL SECURITY INVOKER AS SELECT s.id FROM singers AS s",
                "CREATE TABLE s.albums (id INT64) PRIMARY KEY (id)",
            ]}))],
        );
        let connection = emulated(&mock);
        assert_eq!(
            connection.ddl("", "albums").expect("ddl"),
            "CREATE TABLE albums (\n  id INT64 NOT NULL,\n) PRIMARY KEY(id);\n\n\
             CREATE UNIQUE INDEX albums_by_title ON albums(title) STORING (note);\n\n\
             ALTER TABLE albums ADD CONSTRAINT fk FOREIGN KEY (id) REFERENCES singers (id);"
        );
        assert!(
            connection
                .ddl("", "singer_names")
                .expect("ddl")
                .starts_with("CREATE VIEW")
        );
        assert!(
            connection
                .ddl("s", "albums")
                .expect("ddl")
                .starts_with("CREATE TABLE s.albums")
        );
    }

    fn described(mock: &Mock, table: &str, key: &str, columns: &[(&str, &str)]) {
        reads(
            mock,
            Framing::Array,
            "INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE",
            &[
                metadata(&[("TABLE_SCHEMA", "STRING"), ("TABLE_NAME", "STRING")]),
                json!({"values": ["", table]}),
            ],
        );
        let mut values = Vec::new();
        for (name, kind) in columns {
            values.extend([json!(name), json!(kind), json!("NEVER")]);
        }
        reads(
            mock,
            Framing::Array,
            "FROM INFORMATION_SCHEMA.COLUMNS",
            &[
                metadata(&[
                    ("COLUMN_NAME", "STRING"),
                    ("SPANNER_TYPE", "STRING"),
                    ("IS_GENERATED", "STRING"),
                ]),
                json!({"values": values}),
            ],
        );
        reads(
            mock,
            Framing::Array,
            "INDEX_TYPE = 'PRIMARY_KEY'",
            &[
                metadata(&[("COLUMN_NAME", "STRING")]),
                json!({"values": [key]}),
            ],
        );
    }

    #[test]
    fn rows_are_editable_only_by_a_key_dbdelve_can_write() {
        let mock = Mock::start();
        let result = || run(&emulated(&mock), "SELECT * FROM LABELS").expect("read");
        reads(
            &mock,
            Framing::Array,
            "FROM LABELS",
            &[metadata(&[
                ("name", "STRING"),
                ("rank", "INT64"),
                ("tag", "BYTES"),
            ])],
        );
        let columns = [
            ("name", "STRING(64)"),
            ("rank", "INT64"),
            ("tag", "BYTES(16)"),
        ];
        described(&mock, "labels", "name", &columns);
        let labels = result();
        let target = labels.edit.expect("keyed by a string");
        assert_eq!(
            (target.schema.as_str(), target.table.as_str()),
            ("", "labels")
        );
        assert_eq!(target.keys, [0]);
        // BYTES take no literal the gate admits.
        assert_eq!(
            target.columns,
            [Some("name".into()), Some("rank".into()), None]
        );

        described(&mock, "labels", "rank", &columns);
        let numbered = result().edit.expect("keyed by a number");
        assert_eq!(numbered.keys, [1]);

        described(&mock, "labels", "tag", &columns);
        let tagged = result();
        assert!(tagged.edit.is_none());
        assert!(
            tagged
                .read_only_reason
                .as_deref()
                .is_some_and(|why| why.contains("tag (BYTES(16))")),
            "{:?}",
            tagged.read_only_reason
        );
    }

    #[test]
    fn a_position_is_read_from_the_message_as_line_and_column() {
        assert_eq!(position("x [at 1:8]", "SELECT nope"), Some(7));
        assert_eq!(position("x [at 2:1]", "SELECT\n é"), Some(7));
        assert_eq!(position("no position", "SELECT"), None);
    }
}
