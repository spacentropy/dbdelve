//! How a request to Spanner is signed: by nothing on the emulator, by a
//! token the client signs itself for a service account, or by an access
//! token a user's refresh token buys.
//!
//! Tokens are kept until shortly before they expire, and never logged: a
//! bearer token is the account until it expires.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::signature::RsaKeyPair;
use serde_json::{Value, json};

use super::super::snowflake::{key_der, signed_jwt};
use super::super::{DbError, plain_error};

/// What a self-signed token names as its audience: the service, not a scope.
const AUDIENCE: &str = "https://spanner.googleapis.com/";

/// The most a self-signed token may claim, and what Google's token endpoint
/// hands out.
const LIFETIME: Duration = Duration::from_secs(3600);

/// Minted again once this little of a token's life is left, so one does not
/// expire on its way to the server.
const MARGIN: Duration = Duration::from_secs(300);

const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Where a request's credentials come from.
pub enum Credential {
    /// The emulator, which checks none.
    Emulator,
    /// A service account, which signs its own token.
    ServiceAccount {
        email: String,
        key_id: String,
        key: RsaKeyPair,
    },
    /// A user signed in on this machine, whose refresh token is exchanged.
    User {
        token_uri: String,
        client_id: String,
        client_secret: String,
        refresh_token: String,
        quota_project: Option<String>,
    },
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Emulator => "Emulator",
            Self::ServiceAccount { .. } => "ServiceAccount",
            Self::User { .. } => "User",
        })
    }
}

/// A credential and the token it last produced.
pub struct Auth {
    pub credential: Credential,
    token: Mutex<Option<(String, Instant)>>,
}

impl Auth {
    pub fn new(credential: Credential) -> Self {
        Self {
            credential,
            token: Mutex::new(None),
        }
    }

    /// The headers a request carries: the bearer token, and the project a
    /// user's requests are billed to where their credentials name one.
    pub fn headers(&self, agent: &ureq::Agent) -> Result<Vec<(&'static str, String)>, DbError> {
        let mut headers = Vec::new();
        if matches!(self.credential, Credential::Emulator) {
            return Ok(headers);
        }
        headers.push(("Authorization", format!("Bearer {}", self.token(agent)?)));
        if let Credential::User {
            quota_project: Some(project),
            ..
        } = &self.credential
        {
            headers.push(("x-goog-user-project", project.clone()));
        }
        Ok(headers)
    }

    fn token(&self, agent: &ureq::Agent) -> Result<String, DbError> {
        let mut cached = self
            .token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((token, expires)) = cached.as_ref()
            && expires.saturating_duration_since(Instant::now()) > MARGIN
        {
            return Ok(token.clone());
        }
        let (token, life) = match &self.credential {
            Credential::Emulator => unreachable!("the emulator takes no token"),
            Credential::ServiceAccount { email, key_id, key } => {
                (self_signed(email, key_id, key, epoch_seconds())?, LIFETIME)
            }
            Credential::User {
                token_uri,
                client_id,
                client_secret,
                refresh_token,
                ..
            } => exchanged(agent, token_uri, client_id, client_secret, refresh_token)?,
        };
        *cached = Some((token.clone(), Instant::now() + life));
        Ok(token)
    }
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// A service account's own token for Spanner, good for an hour from `now`:
/// no round trip to a token endpoint.
pub fn self_signed(
    email: &str,
    key_id: &str,
    key: &RsaKeyPair,
    now: u64,
) -> Result<String, DbError> {
    let claims = json!({
        "iss": email,
        "sub": email,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + LIFETIME.as_secs(),
    });
    signed_jwt(
        &json!({"alg": "RS256", "typ": "JWT", "kid": key_id}),
        &claims,
        key,
    )
}

/// An access token for a refresh token, and how long it is good for.
fn exchanged(
    agent: &ureq::Agent,
    token_uri: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<(String, Duration), DbError> {
    let refused = |detail: String| {
        plain_error(format!(
            "The application default credentials were refused: {detail}"
        ))
    };
    let mut response = agent
        .post(token_uri)
        .send_form([
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
        ])
        .map_err(|error| refused(format!("{token_uri} was not reached ({error}).")))?;
    let status = response.status().as_u16();
    let body: Value = response.body_mut().read_json().unwrap_or(Value::Null);
    if status != 200 {
        let detail = body["error_description"]
            .as_str()
            .or_else(|| body["error"].as_str())
            .map_or_else(|| format!("HTTP {status}."), str::to_string);
        return Err(refused(detail));
    }
    let token = body["access_token"]
        .as_str()
        .ok_or_else(|| refused("the answer held no access token.".into()))?;
    let life = body["expires_in"].as_u64().unwrap_or(LIFETIME.as_secs());
    Ok((token.to_string(), Duration::from_secs(life)))
}

/// The credential a profile signs in with: the key file it names, or the
/// application default credentials when it names none.
pub fn credential(private_key: &str) -> Result<Credential, DbError> {
    let path = match private_key.trim() {
        "" => adc_path().ok_or_else(|| {
            plain_error(
                "No application default credentials were found, and no key file is named.".into(),
            )
        })?,
        path => crate::store::home_expanded(path),
    };
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(&path).map_err(|error| {
        plain_error(format!(
            "The credentials at {shown} were not read: {error}."
        ))
    })?;
    from_json(&text, &shown, private_key.trim().is_empty())
}

/// Read apart from the file so a test can hand one in.
pub fn from_json(text: &str, shown: &str, default: bool) -> Result<Credential, DbError> {
    let file: Value = serde_json::from_str(text).map_err(|error| {
        plain_error(format!("The credentials at {shown} are not JSON: {error}."))
    })?;
    let field = |name: &str| {
        file[name]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| plain_error(format!("The credentials at {shown} have no {name}.")))
    };
    match file["type"].as_str() {
        Some("service_account") => {
            let pem = field("private_key")?;
            let key = key_der(&pem)
                .and_then(|der| RsaKeyPair::from_pkcs8(&der).ok())
                .ok_or_else(|| {
                    plain_error(format!(
                        "The credentials at {shown} hold no RSA private key DBDelve can read."
                    ))
                })?;
            Ok(Credential::ServiceAccount {
                email: field("client_email")?,
                key_id: field("private_key_id")?,
                key,
            })
        }
        // A user's sign-in is application default credentials only; a key
        // file named in the form is a service account's.
        Some("authorized_user") if default => Ok(Credential::User {
            token_uri: file["token_uri"].as_str().unwrap_or(TOKEN_URI).to_string(),
            client_id: field("client_id")?,
            client_secret: field("client_secret")?,
            refresh_token: field("refresh_token")?,
            quota_project: file["quota_project_id"].as_str().map(str::to_string),
        }),
        Some(kind) => Err(plain_error(format!(
            "The credentials at {shown} are of type {kind}, which DBDelve does not sign in \
             with: it takes a service account key, or a user's application default credentials."
        ))),
        None => Err(plain_error(format!(
            "The credentials at {shown} name no type."
        ))),
    }
}

/// Where application default credentials are kept: the file the
/// environment names, else the cloud SDK's configuration directory.
fn adc_path() -> Option<PathBuf> {
    adc_path_in(|name| std::env::var_os(name), cfg!(windows))
}

fn adc_path_in(var: impl Fn(&str) -> Option<OsString>, windows: bool) -> Option<PathBuf> {
    let var = |name: &str| var(name).filter(|value| !value.is_empty());
    if let Some(path) = var("GOOGLE_APPLICATION_CREDENTIALS") {
        return Some(path.into());
    }
    let file = "application_default_credentials.json";
    if let Some(config) = var("CLOUDSDK_CONFIG") {
        return Some(PathBuf::from(config).join(file));
    }
    let config = match windows {
        true => PathBuf::from(var("APPDATA")?).join("gcloud"),
        false => PathBuf::from(var("HOME")?).join(".config").join("gcloud"),
    };
    Some(config.join(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_credentials_are_looked_for_where_the_cloud_sdk_keeps_them() {
        let at = |pairs: &[(&str, &str)], windows: bool| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            adc_path_in(
                |name| {
                    pairs
                        .iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, value)| OsString::from(value))
                },
                windows,
            )
        };
        let home = [
            ("HOME", "/Users/ada"),
            ("APPDATA", "C:/Users/ada/AppData/Roaming"),
        ];
        assert_eq!(
            at(&home, false),
            Some("/Users/ada/.config/gcloud/application_default_credentials.json".into())
        );
        assert_eq!(
            at(&home, true),
            Some("C:/Users/ada/AppData/Roaming/gcloud/application_default_credentials.json".into())
        );
        let sdk = [("HOME", "/Users/ada"), ("CLOUDSDK_CONFIG", "/etc/gcloud")];
        assert_eq!(
            at(&sdk, false),
            Some("/etc/gcloud/application_default_credentials.json".into())
        );
        let named = [
            ("CLOUDSDK_CONFIG", "/etc/gcloud"),
            ("GOOGLE_APPLICATION_CREDENTIALS", "/keys/sa.json"),
        ];
        assert_eq!(at(&named, false), Some("/keys/sa.json".into()));
        // Set and empty is not set.
        assert_eq!(
            at(
                &[("GOOGLE_APPLICATION_CREDENTIALS", ""), ("HOME", "/h")],
                false
            ),
            Some("/h/.config/gcloud/application_default_credentials.json".into())
        );
        assert_eq!(at(&[], false), None);
    }
}
