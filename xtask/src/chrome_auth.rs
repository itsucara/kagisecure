//! `cargo xtask chrome-auth` — obtain the Chrome Web Store API refresh token, once.
//!
//! OAuth 2.0 for installed apps: a loopback redirect on `127.0.0.1` at a random port, PKCE
//! (`S256`), and a `state` check. `CWS_CLIENT_ID` and `CWS_CLIENT_SECRET` come from standard input
//! as kagisecure's stdin delivery frame, exactly as for `chrome-publish`.
//!
//! Its one intended caller is kagisecure's `store_command_output` (ADR-0049), which feeds the
//! client credentials through `stdin_environment` and stores what this prints in the vault. So
//! standard output carries **only** the refresh token, one line, and nothing else; every status
//! line goes to standard error. It refuses to run with a terminal on standard output, so the
//! token can never land on a screen or in a transcript.

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::chrome_publish::{SCOPE, Secrets, TOKEN_URL, read_stdin_credentials, send};

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const CONSENT_TIMEOUT: Duration = Duration::from_secs(300);

/// Run the flow and write the refresh token, alone, to standard output.
pub fn chrome_auth() -> Result<()> {
    // Before anything else, so nothing is asked of Google for a token with nowhere safe to go.
    if std::io::stdout().is_terminal() {
        bail!(
            "standard output is a terminal; chrome-auth prints the refresh token there. Run it \
             through kagisecure's store_command_output (docs/chrome-web-store.md §8)"
        );
    }
    let creds = read_stdin_credentials(&["CWS_CLIENT_ID", "CWS_CLIENT_SECRET"])?;
    let (client_id, client_secret) = (&creds["CWS_CLIENT_ID"], &creds["CWS_CLIENT_SECRET"]);
    let mut secrets = Secrets(vec![client_secret.clone()]);

    let verifier = base64url(&random_bytes(32)?);
    let state = base64url(&random_bytes(16)?);
    let listener = TcpListener::bind("127.0.0.1:0").context("binding a loopback port")?;
    let redirect_uri = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let url = consent_url(client_id, &redirect_uri, &challenge(&verifier), &state);

    eprintln!("opening Google's consent page in the browser; sign in as the store's owner");
    eprintln!("if it does not open, visit:\n{url}");
    let _ = Command::new("/usr/bin/open").arg(&url).status();

    let code = receive_code(&listener, &state)?;
    secrets.0.push(code.clone());
    let request = crate::chrome_publish::Request {
        method: "POST",
        url: TOKEN_URL.to_owned(),
        form: vec![
            ("client_id", client_id.clone()),
            ("client_secret", client_secret.clone()),
            ("code", code),
            ("code_verifier", verifier),
            ("grant_type", "authorization_code".to_owned()),
            ("redirect_uri", redirect_uri),
        ],
        ..Default::default()
    };
    let answer = send(&request, &secrets).context("exchanging the authorization code")?;
    let refresh = answer
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .context(
            "Google returned no refresh token; remove the app's access at \
             https://myaccount.google.com/permissions and run this again",
        )?
        .to_owned();
    let mut out = std::io::stdout().lock();
    writeln!(out, "{refresh}").context("writing the refresh token to standard output")?;
    out.flush().context("flushing standard output")?;
    eprintln!("refresh token obtained and written to standard output (not shown)");
    Ok(())
}

/// The consent URL. `access_type=offline` and `prompt=consent` make Google issue a refresh token
/// every time, even for an account that has consented before.
pub fn consent_url(client_id: &str, redirect_uri: &str, challenge: &str, state: &str) -> String {
    let params = [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", SCOPE),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
    ];
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect();
    format!("{AUTH_URL}?{}", query.join("&"))
}

/// PKCE `S256`: base64url(SHA-256(verifier)), unpadded.
pub fn challenge(verifier: &str) -> String {
    base64url(&Sha256::digest(verifier.as_bytes()))
}

/// Unpadded base64url.
pub fn base64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// RFC 3986 percent-encoding of everything but the unreserved characters.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What the redirect carried.
#[derive(Debug, PartialEq, Eq)]
pub enum Redirect {
    /// The authorization code.
    Code(String),
    /// Google (or the owner) refused: the `error` parameter.
    Denied(String),
    /// Not the redirect (a favicon request, say).
    Other,
}

/// Interpret the request line of a loopback request, checking `state`.
pub fn parse_redirect(request_line: &str, expected_state: &str) -> Result<Redirect> {
    let mut parts = request_line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(Redirect::Other);
    };
    let Some(("/", query)) = target.split_once('?') else {
        return Ok(Redirect::Other);
    };
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => error = Some(v),
            _ => {}
        }
    }
    if let Some(e) = error {
        return Ok(Redirect::Denied(e));
    }
    if state.as_deref() != Some(expected_state) {
        bail!("the redirect's state does not match; refusing it");
    }
    code.filter(|c| !c.is_empty())
        .map(Redirect::Code)
        .context("the redirect carries no code")
}

fn receive_code(listener: &TcpListener, state: &str) -> Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + CONSENT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                if let Some(code) = answer(stream, state)? {
                    return Ok(code);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    bail!("no answer from the consent page within {CONSENT_TIMEOUT:?}");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(e).context("accepting the redirect"),
        }
    }
}

fn answer(mut stream: TcpStream, state: &str) -> Result<Option<String>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(16 * 1024)
        .read_line(&mut line)?;
    let (status, text, result) = match parse_redirect(&line, state) {
        Ok(Redirect::Code(code)) => (
            "200 OK",
            "kagisecure: authorized. You can close this tab.",
            Ok(Some(code)),
        ),
        Ok(Redirect::Denied(e)) => (
            "200 OK",
            "kagisecure: authorization was refused.",
            Err(anyhow::anyhow!("consent refused: {e}")),
        ),
        Ok(Redirect::Other) => ("404 Not Found", "", Ok(None)),
        Err(e) => (
            "400 Bad Request",
            "kagisecure: unexpected redirect.",
            Err(e),
        ),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    result
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn consent_url_carries_the_flow_parameters() {
        let url = consent_url("id.apps", "http://127.0.0.1:5555", "CH", "ST");
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?client_id=id.apps&"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5555"));
        assert!(url.contains("scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fchromewebstore"));
        assert!(url.contains("code_challenge=CH&code_challenge_method=S256"));
        assert!(url.contains("access_type=offline&prompt=consent"));
        assert!(url.ends_with("state=ST"));
    }

    #[test]
    fn redirect_is_parsed_and_state_checked() {
        assert_eq!(
            parse_redirect("GET /?state=ST&code=4%2F0Ab&scope=x HTTP/1.1", "ST").unwrap(),
            Redirect::Code("4/0Ab".to_owned())
        );
        assert_eq!(
            parse_redirect("GET /?error=access_denied&state=ST HTTP/1.1", "ST").unwrap(),
            Redirect::Denied("access_denied".to_owned())
        );
        assert_eq!(
            parse_redirect("GET /favicon.ico HTTP/1.1", "ST").unwrap(),
            Redirect::Other
        );
        assert!(parse_redirect("GET /?state=XX&code=c HTTP/1.1", "ST").is_err());
        assert!(parse_redirect("GET /?state=ST HTTP/1.1", "ST").is_err());
    }

    #[test]
    fn percent_round_trip() {
        assert_eq!(percent_decode(&percent_encode("a b/c:%~")), "a b/c:%~");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
