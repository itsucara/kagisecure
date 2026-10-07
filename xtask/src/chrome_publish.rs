//! `cargo xtask chrome-publish` — upload the store package and submit it for review, through the
//! Chrome Web Store API (v2, publisher-scoped; see `docs/chrome-web-store.md`, "Publishing with
//! the API").
//!
//! Chrome does not let any extension script the Web Store's own pages, so the dashboard cannot be
//! automated from a browser; the API is the only unattended path.
//!
//! **Credentials come only from standard input**, as kagisecure's stdin delivery frame (ADR-0047):
//! `NAME\0VALUE\0` pairs, then end of file. Nothing is read from the environment, the command line
//! or a file, and no value is ever printed: every request carrying one is written to curl's
//! standard input as a config file (`--config -`), never to argv, and every response body shown in
//! an error has the values redacted first.
//!
//! HTTP goes through `/usr/bin/curl`, as `sparkle.rs` already does, so the workspace gains no HTTP
//! client and no TLS stack for one release task. The absolute path matters: kagisecure starts
//! `run_with_env` children with a minimal `PATH`.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::version;

/// The kagisecure developer account's publisher id.
pub const PUBLISHER_ID: &str = "3edd5ef8-a197-45cc-b770-5ba58afbefa3";
/// The store item's id.
pub const ITEM_ID: &str = "jgfpjhijkkjngmihmammolbcicgkicji";

/// Google's OAuth 2.0 token endpoint.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// The only scope the Chrome Web Store API takes.
pub const SCOPE: &str = "https://www.googleapis.com/auth/chromewebstore";

const API: &str = "https://chromewebstore.googleapis.com";
const CURL: &str = "/usr/bin/curl";

/// How long an asynchronous upload may stay `IN_PROGRESS` before this gives up.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Options for [`chrome_publish`].
pub struct Options {
    /// The package to upload; the current version's `dist/` zip when `None`.
    pub zip: Option<PathBuf>,
    /// Check everything that can be checked offline and print the plan; send nothing.
    pub dry_run: bool,
}

/// Parse `[--zip PATH] [--dry-run]`.
pub fn parse_args(flags: &[&str]) -> Result<Options> {
    let mut options = Options {
        zip: None,
        dry_run: false,
    };
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        match *flag {
            "--dry-run" => options.dry_run = true,
            "--zip" => {
                let path = it.next().context("--zip needs a path")?;
                options.zip = Some(PathBuf::from(path));
            }
            other => bail!("unknown flag {other:?}"),
        }
    }
    Ok(options)
}

/// Upload, wait for the upload to be processed, submit for review, report.
pub fn chrome_publish(root: &Path, options: &Options) -> Result<()> {
    let version = version::workspace_version(root)?;
    let zip = match &options.zip {
        Some(path) => path.clone(),
        None => root
            .join("dist")
            .join(format!("kagisecure-chrome-{version}.zip")),
    };
    if !zip.is_file() {
        bail!(
            "{} does not exist; build it with `cargo xtask chrome-package`",
            zip.display()
        );
    }
    check_zip_version(&zip, &version)?;

    let creds =
        read_stdin_credentials(&["CWS_CLIENT_ID", "CWS_CLIENT_SECRET", "CWS_REFRESH_TOKEN"])?;
    let secrets = Secrets(creds.values().cloned().collect());

    if options.dry_run {
        println!("dry run: nothing is sent");
        println!("  package   {} (manifest version {version})", zip.display());
        println!("  item      {ITEM_ID} (publisher {PUBLISHER_ID})");
        println!("  token     POST {TOKEN_URL}");
        println!("  upload    POST {}", upload_url());
        println!("  poll      GET  {}", item_url("fetchStatus"));
        println!("  submit    POST {}", item_url("publish"));
        return Ok(());
    }

    let token = access_token(
        &creds["CWS_CLIENT_ID"],
        &creds["CWS_CLIENT_SECRET"],
        &creds["CWS_REFRESH_TOKEN"],
        &secrets,
    )?;
    let secrets = secrets.with(token.clone());

    println!("uploading {} to item {ITEM_ID}", zip.display());
    let upload = send(&upload_request(&token, &zip), &secrets).context("upload")?;
    let mut state = str_field(&upload, "uploadState");
    let started = Instant::now();
    while state == "IN_PROGRESS" {
        if started.elapsed() > UPLOAD_TIMEOUT {
            bail!("the upload is still IN_PROGRESS after {UPLOAD_TIMEOUT:?}; check the dashboard");
        }
        std::thread::sleep(POLL_INTERVAL);
        let status = send(&status_request(&token), &secrets).context("fetchStatus")?;
        state = str_field(&status, "lastAsyncUploadState");
    }
    if state != "SUCCEEDED" {
        bail!(
            "the upload ended in state {state:?}: {}",
            secrets.redact(&upload.to_string())
        );
    }
    let uploaded = match str_field(&upload, "crxVersion") {
        v if v.is_empty() => version.clone(),
        v => v,
    };
    if uploaded != version {
        bail!("the store read version {uploaded} from the upload, expected {version}");
    }
    println!("upload succeeded: version {uploaded}");

    let published = send(&publish_request(&token), &secrets).context("publish")?;
    if let Some(warnings) = published.get("warningInfo") {
        println!("warnings: {}", secrets.redact(&warnings.to_string()));
    }

    let status = send(&status_request(&token), &secrets).context("fetchStatus")?;
    let submitted = status.get("submittedItemRevisionStatus");
    let submitted_state = submitted
        .and_then(|s| s.get("state"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            published
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or("?")
        });
    println!("item      {ITEM_ID}");
    println!("version   {uploaded}");
    println!("state     {submitted_state}");
    if let Some(live) = status
        .pointer("/publishedItemRevisionStatus/distributionChannels/0/crxVersion")
        .and_then(Value::as_str)
    {
        println!("live      {live}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Credentials

/// Read kagisecure's stdin frame and return exactly the `names` asked for.
///
/// Refuses a terminal on standard input: credentials are never typed here.
pub fn read_stdin_credentials(names: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!(
            "credentials are read from standard input as kagisecure's stdin delivery frame \
             (NAME\\0VALUE\\0 pairs); run this through kagisecure with stdin delivery"
        );
    }
    let mut raw = Vec::new();
    stdin
        .read_to_end(&mut raw)
        .context("reading standard input")?;
    let frame = parse_frame(&raw)?;
    pick(frame, names)
}

/// Parse `NAME\0VALUE\0` pairs. Strict: a missing terminator, an odd field count, an empty or
/// malformed name, non-UTF-8 or a repeated name is refused, and no value appears in any error.
pub fn parse_frame(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    if raw.is_empty() {
        bail!("standard input is empty; expected kagisecure's stdin delivery frame");
    }
    let Some(body) = raw.strip_suffix(b"\0") else {
        bail!("the stdin frame does not end with a NUL byte");
    };
    let fields: Vec<&[u8]> = body.split(|b| *b == 0).collect();
    if !fields.len().is_multiple_of(2) {
        bail!("the stdin frame has a name without a value");
    }
    let mut out = BTreeMap::new();
    for pair in fields.chunks(2) {
        let name =
            std::str::from_utf8(pair[0]).context("a name in the stdin frame is not UTF-8")?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            bail!("the stdin frame has an invalid variable name {name:?}");
        }
        let value = String::from_utf8(pair[1].to_vec())
            .map_err(|_| anyhow::anyhow!("the value of {name} is not UTF-8"))?;
        if out.insert(name.to_owned(), value).is_some() {
            bail!("the stdin frame names {name} twice");
        }
    }
    Ok(out)
}

/// Keep `names`, all of which must be present and non-empty. Other names are ignored.
pub fn pick(
    mut frame: BTreeMap<String, String>,
    names: &[&str],
) -> Result<BTreeMap<String, String>> {
    let missing: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| frame.get(*n).is_none_or(String::is_empty))
        .collect();
    if !missing.is_empty() {
        bail!(
            "the stdin frame lacks {}; the kagisecure environment must provide them",
            missing.join(", ")
        );
    }
    Ok(names
        .iter()
        .map(|n| ((*n).to_owned(), frame.remove(*n).unwrap_or_default()))
        .collect())
}

/// Values that must never be shown; [`Secrets::redact`] removes them from text.
pub struct Secrets(pub Vec<String>);

impl Secrets {
    /// The same set plus one more value.
    #[must_use]
    pub fn with(mut self, value: String) -> Self {
        self.0.push(value);
        self
    }

    /// `text` with every known value replaced.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for s in self.0.iter().filter(|s| !s.is_empty()) {
            out = out.replace(s.as_str(), "[redacted]");
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// The package

/// The `version` in the zip's `manifest.json` must be `expected`.
pub fn check_zip_version(zip: &Path, expected: &str) -> Result<()> {
    let file = std::fs::File::open(zip).with_context(|| format!("opening {}", zip.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("reading {} as a zip", zip.display()))?;
    let mut text = String::new();
    archive
        .by_name("manifest.json")
        .with_context(|| format!("{} has no manifest.json at its root", zip.display()))?
        .read_to_string(&mut text)?;
    let found = manifest_version(&text)?;
    if found != expected {
        bail!(
            "{} carries manifest version {found}, the workspace is at {expected}; \
             rebuild it with `cargo xtask chrome-package`",
            zip.display()
        );
    }
    Ok(())
}

/// The `version` field of a manifest.
pub fn manifest_version(text: &str) -> Result<String> {
    let manifest: Value = serde_json::from_str(text).context("manifest.json is not JSON")?;
    manifest
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("manifest.json has no string `version`")
}

// ---------------------------------------------------------------------------------------------
// Requests

/// One HTTP request, rendered as a curl config file so nothing reaches argv.
#[derive(Debug, Default)]
pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<String>,
    /// `application/x-www-form-urlencoded` fields.
    pub form: Vec<(&'static str, String)>,
    /// A file sent as the raw body.
    pub upload: Option<PathBuf>,
}

fn upload_url() -> String {
    format!("{API}/upload/v2/publishers/{PUBLISHER_ID}/items/{ITEM_ID}:upload")
}

fn item_url(method: &str) -> String {
    format!("{API}/v2/publishers/{PUBLISHER_ID}/items/{ITEM_ID}:{method}")
}

fn bearer(token: &str) -> String {
    format!("Authorization: Bearer {token}")
}

/// Exchange a refresh token for an access token.
pub fn refresh_request(client_id: &str, client_secret: &str, refresh_token: &str) -> Request {
    Request {
        method: "POST",
        url: TOKEN_URL.to_owned(),
        form: vec![
            ("client_id", client_id.to_owned()),
            ("client_secret", client_secret.to_owned()),
            ("refresh_token", refresh_token.to_owned()),
            ("grant_type", "refresh_token".to_owned()),
        ],
        ..Request::default()
    }
}

/// `media.upload`: the zip as the raw body.
pub fn upload_request(token: &str, zip: &Path) -> Request {
    Request {
        method: "POST",
        url: upload_url(),
        headers: vec![bearer(token), "Content-Type: application/zip".to_owned()],
        upload: Some(zip.to_path_buf()),
        ..Request::default()
    }
}

/// `publishers.items.fetchStatus`.
pub fn status_request(token: &str) -> Request {
    Request {
        method: "GET",
        url: item_url("fetchStatus"),
        headers: vec![bearer(token)],
        ..Request::default()
    }
}

/// `publishers.items.publish` with an empty body: the default publish type, which submits the
/// uploaded revision for review and publishes it once approved.
pub fn publish_request(token: &str) -> Request {
    Request {
        method: "POST",
        url: item_url("publish"),
        headers: vec![bearer(token), "Content-Length: 0".to_owned()],
        ..Request::default()
    }
}

/// A curl config string: `"` and `\` escaped. Line breaks cannot be expressed and are refused.
fn quote(value: &str) -> Result<String> {
    if value.contains(['\n', '\r']) {
        bail!("a request value contains a line break");
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// Render `request` as the config curl reads from standard input.
pub fn curl_config(request: &Request) -> Result<String> {
    let mut out = String::new();
    out.push_str(&format!("url = {}\n", quote(&request.url)?));
    out.push_str(&format!("request = {}\n", quote(request.method)?));
    for header in &request.headers {
        out.push_str(&format!("header = {}\n", quote(header)?));
    }
    for (name, value) in &request.form {
        out.push_str(&format!(
            "data-urlencode = {}\n",
            quote(&format!("{name}={value}"))?
        ));
    }
    if let Some(path) = &request.upload {
        let path = path.to_str().context("the package path is not UTF-8")?;
        out.push_str(&format!("upload-file = {}\n", quote(path)?));
    }
    Ok(out)
}

/// Send `request` and return the JSON body of a 2xx answer; anything else fails with Google's
/// own error message, redacted.
pub fn send(request: &Request, secrets: &Secrets) -> Result<Value> {
    let config = curl_config(request)?;
    let mut child = Command::new(CURL)
        .args(["--silent", "--show-error", "--config", "-"])
        .args(["--write-out", "\n%{http_code}"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {CURL}"))?;
    child
        .stdin
        .take()
        .context("curl's standard input")?
        .write_all(config.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "{} {} failed: {}",
            request.method,
            request.url,
            secrets.redact(String::from_utf8_lossy(&output.stderr).trim())
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    interpret(code.trim(), body, secrets)
        .with_context(|| format!("{} {}", request.method, request.url))
}

/// Turn a status code and body into JSON or an error carrying Google's message.
pub fn interpret(code: &str, body: &str, secrets: &Secrets) -> Result<Value> {
    let ok = code.starts_with('2');
    let json: Option<Value> = serde_json::from_str(body).ok();
    if ok {
        return json.with_context(|| format!("HTTP {code}: the answer is not JSON"));
    }
    let message = json.as_ref().and_then(|j| {
        let err = j.get("error")?;
        if let Some(text) = err.as_str() {
            // OAuth endpoint: {"error": "invalid_grant", "error_description": "..."}
            let desc = j
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("");
            return Some(format!("{text}: {desc}"));
        }
        let msg = err.get("message").and_then(Value::as_str).unwrap_or("");
        let status = err.get("status").and_then(Value::as_str).unwrap_or("");
        Some(format!("{status}: {msg}"))
    });
    bail!(
        "HTTP {code}: {}",
        secrets.redact(&message.unwrap_or_else(|| body.trim().to_owned()))
    )
}

fn str_field(value: &Value, name: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Exchange the refresh token for an access token.
fn access_token(
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
    secrets: &Secrets,
) -> Result<String> {
    let answer = send(
        &refresh_request(client_id, client_secret, refresh_token),
        secrets,
    )
    .context(
        "refreshing the access token (an `invalid_grant` means the refresh token expired or was \
         revoked: run `cargo xtask chrome-auth` again)",
    )?;
    let token = str_field(&answer, "access_token");
    if token.is_empty() {
        bail!("the token endpoint answered without an access_token");
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_parses_pairs() {
        let f = parse_frame(b"A\0one\0B_2\0\0").unwrap();
        assert_eq!(f["A"], "one");
        assert_eq!(f["B_2"], "");
    }

    #[test]
    fn frame_refuses_malformed_input() {
        assert!(parse_frame(b"").is_err());
        assert!(parse_frame(b"A\0one").is_err());
        assert!(parse_frame(b"A\0").is_err());
        assert!(parse_frame(b"\0v\0").is_err());
        assert!(parse_frame(b"A-B\0v\0").is_err());
        assert!(parse_frame(b"A\0\xff\0").is_err());
        assert!(parse_frame(b"A\0x\0A\0y\0").is_err());
    }

    #[test]
    fn frame_errors_never_contain_values() {
        let err = parse_frame(b"A\0hunter2\0A\0hunter3\0").unwrap_err();
        assert!(!format!("{err:#}").contains("hunter"));
    }

    #[test]
    fn pick_requires_every_name() {
        let f = parse_frame(b"A\0x\0EXTRA\0y\0").unwrap();
        let got = pick(f.clone(), &["A"]).unwrap();
        assert_eq!(got.len(), 1);
        let err = pick(f, &["A", "B"]).unwrap_err();
        assert!(format!("{err}").contains('B'));
        let empty = parse_frame(b"A\0\0").unwrap();
        assert!(pick(empty, &["A"]).is_err());
    }

    #[test]
    fn manifest_version_is_read() {
        assert_eq!(manifest_version(r#"{"version":"0.2.0"}"#).unwrap(), "0.2.0");
        assert!(manifest_version(r#"{"version":2}"#).is_err());
        assert!(manifest_version("nope").is_err());
    }

    #[test]
    fn zip_version_must_match() {
        let dir = std::env::temp_dir().join(format!("xtask-cws-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.zip");
        let mut w = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        w.start_file("manifest.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(br#"{"version":"1.2.3"}"#).unwrap();
        w.finish().unwrap();
        assert!(check_zip_version(&path, "1.2.3").is_ok());
        assert!(check_zip_version(&path, "1.2.4").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn requests_target_the_v2_publisher_endpoints() {
        let up = upload_request("tok", Path::new("/tmp/p.zip"));
        assert_eq!(
            up.url,
            "https://chromewebstore.googleapis.com/upload/v2/publishers/\
             3edd5ef8-a197-45cc-b770-5ba58afbefa3/items/jgfpjhijkkjngmihmammolbcicgkicji:upload"
        );
        assert!(
            publish_request("t")
                .url
                .ends_with("/items/jgfpjhijkkjngmihmammolbcicgkicji:publish")
        );
        assert_eq!(status_request("t").method, "GET");
        assert!(status_request("t").url.contains("/v2/publishers/"));
    }

    #[test]
    fn curl_config_carries_secrets_only_on_stdin_and_escapes() {
        let cfg = curl_config(&refresh_request("id", "se\"c\\ret", "rt")).unwrap();
        assert!(cfg.contains("url = \"https://oauth2.googleapis.com/token\"\n"));
        assert!(cfg.contains("data-urlencode = \"client_secret=se\\\"c\\\\ret\"\n"));
        assert!(cfg.contains("data-urlencode = \"grant_type=refresh_token\"\n"));
        let cfg = curl_config(&upload_request("tok", Path::new("/a b/p.zip"))).unwrap();
        assert!(cfg.contains("header = \"Authorization: Bearer tok\"\n"));
        assert!(cfg.contains("upload-file = \"/a b/p.zip\"\n"));
        assert!(cfg.contains("request = \"POST\"\n"));
        assert!(curl_config(&refresh_request("id", "a\nb", "rt")).is_err());
    }

    #[test]
    fn errors_show_googles_message_redacted() {
        let s = Secrets(vec!["sekrit".to_owned()]);
        let e = interpret(
            "400",
            r#"{"error":"invalid_grant","error_description":"Bad sekrit"}"#,
            &s,
        )
        .unwrap_err();
        assert_eq!(format!("{e}"), "HTTP 400: invalid_grant: Bad [redacted]");
        let e = interpret(
            "403",
            r#"{"error":{"code":403,"message":"denied","status":"PERMISSION_DENIED"}}"#,
            &s,
        )
        .unwrap_err();
        assert_eq!(format!("{e}"), "HTTP 403: PERMISSION_DENIED: denied");
        assert_eq!(
            interpret("200", r#"{"uploadState":"SUCCEEDED"}"#, &s).unwrap()["uploadState"],
            "SUCCEEDED"
        );
    }

    #[test]
    fn args_parse() {
        let o = parse_args(&["--zip", "x.zip", "--dry-run"]).unwrap();
        assert!(o.dry_run);
        assert_eq!(o.zip.unwrap(), PathBuf::from("x.zip"));
        assert!(parse_args(&["--zip"]).is_err());
        assert!(parse_args(&["--bogus"]).is_err());
    }
}
