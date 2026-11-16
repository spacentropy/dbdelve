//! A stand-in for Spanner's REST API, so the connection is tested in a plain
//! `cargo test` with no project and no network.
//!
//! Nothing here was recorded from the service: the shapes are Google's REST
//! reference's, and the emulator's where the two differ. A stream is served
//! either way the two frame one: the service's JSON array of
//! `PartialResultSet`s, or the emulator's `{"result": …}` a line.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::SpannerConfig;

pub const DATABASE: &str = "projects/p/instances/i/databases/d";

/// How a stream's messages are put on the wire.
#[derive(Clone, Copy, Debug)]
pub enum Framing {
    /// The service: one JSON array.
    Array,
    /// The emulator: one `{"result": …}` object a line.
    Lines,
}

#[derive(Clone, Debug)]
pub struct Response {
    status: u16,
    body: Vec<u8>,
    /// Bytes sent, then a pause before the rest; `None` sends it whole.
    stall: Option<(usize, Duration)>,
}

impl Response {
    pub fn json(status: u16, body: Value) -> Self {
        Self::text(status, &body.to_string())
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.as_bytes().to_vec(),
            stall: None,
        }
    }

    /// A streamed result, framed as `framing` frames one.
    pub fn stream(framing: Framing, messages: &[Value]) -> Self {
        let body = match framing {
            Framing::Array => format!(
                "[{}]",
                messages
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join(",\n")
            ),
            Framing::Lines => messages
                .iter()
                .map(|message| format!("{}\n", json!({"result": message})))
                .collect(),
        };
        Self::text(200, &body)
    }

    /// `sent` bytes, then nothing for `pause`, then the rest.
    pub fn stalled(self, sent: usize, pause: Duration) -> Self {
        Self {
            stall: Some((sent, pause)),
            ..self
        }
    }
}

/// A result's first message: its columns, `(name, type code)`.
pub fn metadata(columns: &[(&str, &str)]) -> Value {
    json!({"metadata": {"rowType": {"fields": columns
        .iter()
        .map(|(name, code)| json!({"name": name, "type": {"code": code}}))
        .collect::<Vec<_>>()}}})
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    /// The path below `/v1/`, with its query.
    pub target: String,
    pub headers: Vec<(String, String)>,
    /// `Null` when there was none or it was not JSON.
    pub body: Value,
    pub raw: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct Route {
    method: String,
    /// Matched against the end of the target.
    suffix: String,
    /// Matched against the request's body as text; empty matches anything.
    body: String,
    responses: VecDeque<Response>,
}

#[derive(Default)]
struct State {
    routes: Vec<Route>,
    requests: Vec<Request>,
}

pub struct Mock {
    pub address: String,
    state: Arc<Mutex<State>>,
}

impl Mock {
    /// Listening on a free loopback port, already making sessions and
    /// answering the connect's dialect read for a GoogleSQL database.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = format!("http://{}", listener.local_addr().expect("bound"));
        let state = Arc::<Mutex<State>>::default();
        let shared = Arc::clone(&state);
        // ponytail: never joined; the listener lives until the test binary
        // exits, as Snowflake's does.
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let state = Arc::clone(&shared);
                std::thread::spawn(move || serve(stream, &state));
            }
        });
        let mock = Self { address, state };
        mock.on(
            "POST",
            "/sessions",
            "multiplexed",
            [Response::json(
                200,
                json!({"name": format!("{DATABASE}/sessions/reads")}),
            )],
        );
        mock.on(
            "POST",
            "/sessions",
            "{}",
            [Response::json(
                200,
                json!({"name": format!("{DATABASE}/sessions/writes")}),
            )],
        );
        mock.dialect("GOOGLE_STANDARD_SQL");
        mock
    }

    pub fn dialect(&self, dialect: &str) {
        self.on(
            "POST",
            ":executeStreamingSql",
            "DATABASE_OPTIONS",
            [Response::stream(
                Framing::Array,
                &[
                    metadata(&[("OPTION_VALUE", "STRING")]),
                    json!({"values": [dialect]}),
                ],
            )],
        );
    }

    /// The base the connection is opened against.
    pub fn base(&self) -> String {
        format!("{}/v1/", self.address)
    }

    pub fn config(&self) -> SpannerConfig {
        SpannerConfig {
            project: "p".into(),
            instance: "i".into(),
            database: "d".into(),
            ..SpannerConfig::default()
        }
    }

    /// Answer `method` on a target ending in `suffix` whose body holds
    /// `body`, with `responses` in turn, repeating the last. The newest
    /// route that matches wins.
    pub fn on(
        &self,
        method: &str,
        suffix: &str,
        body: &str,
        responses: impl IntoIterator<Item = Response>,
    ) {
        let responses: VecDeque<_> = responses.into_iter().collect();
        assert!(!responses.is_empty(), "a route needs a response");
        self.state.lock().expect("unpoisoned").routes.push(Route {
            method: method.into(),
            suffix: suffix.into(),
            body: body.into(),
            responses,
        });
    }

    pub fn requests(&self) -> Vec<Request> {
        self.state.lock().expect("unpoisoned").requests.clone()
    }

    /// The requests to a target ending in `suffix`.
    pub fn sent(&self, suffix: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|request| request.target.ends_with(suffix))
            .collect()
    }
}

fn serve(stream: TcpStream, state: &Mutex<State>) {
    let Some(request) = read_request(&stream) else {
        return;
    };
    let response = {
        let mut state = state.lock().expect("unpoisoned");
        state.requests.push(request.clone());
        state
            .routes
            .iter_mut()
            .rev()
            .find(|route| {
                route.method == request.method
                    && request.target.ends_with(&route.suffix)
                    && request.raw.contains(&route.body)
            })
            .map(|route| match route.responses.len() {
                1 => route.responses[0].clone(),
                _ => route.responses.pop_front().expect("not empty"),
            })
    };
    let response = response.unwrap_or_else(|| {
        let message = format!("mock: no route for {} {}", request.method, request.target);
        Response::json(404, json!({"error": {"code": 404, "message": message}}))
    });
    let _ = write_response(stream, &response);
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let target = target.strip_prefix("/v1/").unwrap_or(target).to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let Some((name, value)) = line.trim_end().split_once(':') else {
            break;
        };
        headers.push((name.to_string(), value.trim().to_string()));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    let raw = String::from_utf8_lossy(&body).into_owned();
    Some(Request {
        method,
        target,
        headers,
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
        raw,
    })
}

fn write_response(mut stream: TcpStream, response: &Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    stream.write_all(head.as_bytes())?;
    match response.stall {
        Some((sent, pause)) => {
            let sent = sent.min(response.body.len());
            stream.write_all(&response.body[..sent])?;
            stream.flush()?;
            std::thread::sleep(pause);
            stream.write_all(&response.body[sent..])?;
        }
        None => stream.write_all(&response.body)?,
    }
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Both)
}
