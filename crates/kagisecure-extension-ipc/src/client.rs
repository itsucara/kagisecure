//! The native host's half: connect to the app's extension socket and do one round trip at a time.
//!
//! Blocking and synchronous, like `kagisecure_ipc::client`, and for the same reason: a native
//! messaging host is a single-threaded pipe between two blocking endpoints, and an async runtime
//! would be three dependencies and a scheduler in a process whose entire job is `read`, `write`,
//! `read`, `write`.
//!
//! # Duplex
//!
//! Once the app can speak first (ADR-0036 §3.1), a [`Push`] can arrive at any moment — between two
//! requests, or between a request and its reply. [`Client::into_duplex`] turns a connection into a
//! [`DuplexClient`], whose calls still block until their own reply, while pushes are handed to a
//! channel as they arrive. Replies are routed to their callers by correlation id, so a push that
//! lands mid-call is neither taken for the reply nor lost.

use std::collections::HashMap;
use std::io::BufWriter;
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};

use kagisecure_ipc::connect::ClientStream;
use kagisecure_ipc::endpoint::Endpoint;

use crate::frame::{self, FrameError};
use crate::protocol::{Envelope, HostBound, Push, Request, Response};

/// Why a call to the app did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Nothing is listening: the app is not running.
    #[error(
        "kagisecure is not running. Open the Kagisecure app and unlock your vault, then try again."
    )]
    AppNotRunning,
    /// Something answered, but as another account: the named pipe is not owned by this user.
    /// Nothing was sent to it. Windows only — see `kagisecure_ipc::client::server_is_same_user`.
    #[error(
        "the kagisecure extension endpoint is held by a process of another account; nothing was \
         sent to it"
    )]
    ForeignServer,
    /// The socket path could not be worked out.
    #[error("{0}")]
    Endpoint(#[from] kagisecure_ipc::endpoint::EndpointError),
    /// Wire failure.
    #[error("{0}")]
    Frame(#[from] FrameError),
    /// The app answered a different request than the one that was asked.
    #[error("the app replied to {got:?} when {want:?} was asked")]
    Correlation {
        /// The id that came back.
        got: String,
        /// The id that went out.
        want: String,
    },
    /// A [`DuplexClient`] call used an id another call on the same connection is still waiting
    /// on. Nothing was sent: two replies with one id could not be told apart.
    #[error("a call with id {0:?} is already waiting for its reply")]
    IdInUse(String),
}

/// A connection to the app's extension socket.
pub struct Client {
    reader: ClientStream,
    writer: BufWriter<ClientStream>,
}

impl Client {
    /// Connect to `endpoint`.
    ///
    /// # Errors
    ///
    /// [`ClientError::AppNotRunning`] when nothing is listening — the common case, and the one
    /// the popup turns into "Open Kagisecure" rather than a stack trace.
    pub fn connect(endpoint: &Endpoint) -> Result<Self, ClientError> {
        // A malformed endpoint is a wire-setup failure, not an absent app: checked separately so
        // it keeps its own error rather than reading as "not running".
        endpoint.name().map_err(FrameError::Io)?;
        // `kagisecure_ipc::connect::open`, shared with the MCP client: on Windows it waits a
        // bounded time for a busy pipe (`PIPE_BUSY_WAIT`) where `interprocess`'s connect waits
        // forever, and it opens the pipe with identification-only impersonation. A name that
        // stays busy that long is held by instances nobody is going to free — a stopped
        // listener's leftover connections, or a squatter's — and a native host parked on one
        // would never answer the extension, never read stdin again, and so never notice the
        // browser close the port. Busy and absent are both "the app is not answering".
        let stream =
            kagisecure_ipc::connect::open(endpoint).map_err(|_| ClientError::AppNotRunning)?;
        // Before a single byte goes out — this channel carries what the browser sends, and the
        // fill values that come back — check that the pipe reached is this user's. A name
        // another account created first would otherwise be talked to as if it were the app.
        #[cfg(windows)]
        if !kagisecure_ipc::client::server_is_same_user(&stream) {
            return Err(ClientError::ForeignServer);
        }
        // Lock step, as `ClientStream::try_clone` requires: `call` writes a request, then reads
        // its reply, on one thread.
        let reader = stream.try_clone().map_err(FrameError::Io)?;
        Ok(Self {
            reader,
            writer: BufWriter::new(stream),
        })
    }

    /// Connect to the per-user extension endpoint.
    ///
    /// # Errors
    ///
    /// As [`Client::connect`], plus [`ClientError::Endpoint`] if the path cannot be determined.
    pub fn connect_default() -> Result<Self, ClientError> {
        let endpoint = crate::endpoint::extension_endpoint()?;
        Self::connect(&endpoint)
    }

    /// Send one request and read its reply.
    ///
    /// The correlation id is checked rather than assumed. This connection is used by one thread
    /// in lock step, so a mismatch means the app is confused, not that a reply arrived early —
    /// and answering a `Fill` with the reply to somebody else's `Fill` is exactly the bug worth
    /// failing loudly on.
    ///
    /// # Errors
    ///
    /// [`ClientError::Frame`] on a wire failure, [`ClientError::Correlation`] if the reply is for
    /// a different request.
    pub fn call(&mut self, id: &str, request: &Request) -> Result<Response, ClientError> {
        frame::write(&mut self.writer, &Envelope::new(id, request))?;
        let reply: Envelope<Response> = frame::read(&mut self.reader)?;
        if reply.id != id {
            return Err(ClientError::Correlation {
                got: reply.id,
                want: id.to_owned(),
            });
        }
        Ok(reply.body)
    }

    /// Turn this connection into one that also receives [`Push`]es.
    ///
    /// Returns the client and the receiving end of the channel pushes are delivered to, in the
    /// order they arrived. Dropping the receiver discards pushes; calls are unaffected.
    ///
    /// On Unix a reader thread owns the reading half from here on: it routes each reply to the
    /// call waiting on its id and each push to the channel, so a push is delivered even while no
    /// call is in flight. The thread ends when the app closes the connection — which it does on a
    /// vault lock or a stop — or with the process; dropping the [`DuplexClient`] alone does not
    /// end it, because the reading half is still open.
    ///
    /// On Windows the client end is a synchronous pipe handle whose clones share one file object,
    /// so a read parked on one would block every write on the other. There the client stays in
    /// lock step: a call writes its request and reads until its own reply, delivering any push it
    /// passes on the way, and a push that arrives while no call is in flight waits for the next
    /// one. Windows never offers agent fills (ADR-0036 §12), so no push is sent there today.
    ///
    /// # Errors
    ///
    /// [`ClientError::Frame`] if the reader thread cannot be started.
    pub fn into_duplex(self) -> Result<(DuplexClient, Receiver<Push>), ClientError> {
        let mode = if cfg!(windows) {
            ReadMode::LockStep
        } else {
            ReadMode::Background
        };
        self.into_duplex_mode(mode)
    }

    /// [`Self::into_duplex`] with the read mode chosen by the caller, so the tests can run the
    /// Windows lock-step mode on every platform.
    pub(crate) fn into_duplex_mode(
        self,
        mode: ReadMode,
    ) -> Result<(DuplexClient, Receiver<Push>), ClientError> {
        let (pushes, received) = channel();
        let reading = match mode {
            ReadMode::Background => {
                let routes = Arc::new(Routes::default());
                let thread_routes = Arc::clone(&routes);
                let reader = self.reader;
                std::thread::Builder::new()
                    .name("kagisecure-extension-reader".to_owned())
                    .spawn(move || read_until_closed(reader, &thread_routes, &pushes))
                    .map_err(FrameError::Io)?;
                Reading::Background(routes)
            }
            ReadMode::LockStep => Reading::LockStep {
                reader: Mutex::new(self.reader),
                pushes,
            },
        };
        Ok((
            DuplexClient {
                writer: Mutex::new(self.writer),
                reading,
            },
            received,
        ))
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client { .. }")
    }
}

/// How a [`DuplexClient`] reads. See [`Client::into_duplex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadMode {
    /// A reader thread routes every frame as it arrives.
    Background,
    /// Each call reads until its own reply.
    LockStep,
}

/// A connection to the app's extension socket that receives [`Push`]es as well as replies. From
/// [`Client::into_duplex`].
///
/// Calls may be made from several threads at once; each blocks until the reply with its own id
/// arrives. Frames are written whole under a lock, so two calls never interleave their bytes.
pub struct DuplexClient {
    writer: Mutex<BufWriter<ClientStream>>,
    reading: Reading,
}

enum Reading {
    Background(Arc<Routes>),
    LockStep {
        reader: Mutex<ClientStream>,
        pushes: Sender<Push>,
    },
}

/// Who is waiting for which reply, shared between the calls and the reader thread.
#[derive(Default)]
struct Routes {
    state: Mutex<RouteState>,
}

#[derive(Default)]
struct RouteState {
    waiting: HashMap<String, SyncSender<Result<Response, ClientError>>>,
    /// Set once the reader has stopped: nothing will ever answer a call made after it.
    ended: bool,
}

impl Routes {
    fn state(&self) -> MutexGuard<'_, RouteState> {
        // The map is never left half-updated — every mutation is one `insert` or `remove` — so a
        // panic elsewhere while it was held leaves nothing to distrust.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Stop routing: answer every waiting call with `error_for(its id)`, and every later one with
    /// [`FrameError::Closed`].
    fn end(&self, error_for: impl Fn(&str) -> ClientError) {
        let waiting = {
            let mut state = self.state();
            state.ended = true;
            std::mem::take(&mut state.waiting)
        };
        for (id, waiter) in waiting {
            let _ = waiter.send(Err(error_for(&id)));
        }
    }
}

/// The reader thread's loop: route every frame until the connection ends or goes out of sync.
fn read_until_closed(mut reader: ClientStream, routes: &Routes, pushes: &Sender<Push>) {
    loop {
        match frame::read::<_, HostBound>(&mut reader) {
            Ok(HostBound::Push(push)) => {
                // Nobody listening is a caller that does not want pushes: not an error.
                let _ = pushes.send(push);
            }
            Ok(HostBound::Reply(reply)) => {
                let waiter = routes.state().waiting.remove(&reply.id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send(Ok(reply.body));
                } else {
                    // A reply nobody asked for: every call registers before it writes, so this is
                    // the app confused, not a reply that came early. Fail loudly, as `call` does,
                    // and stop — nothing read after it can be trusted to answer what it seems to.
                    routes.end(|want| ClientError::Correlation {
                        got: reply.id.clone(),
                        want: want.to_owned(),
                    });
                    return;
                }
            }
            // A frame read in full that did not parse. The stream is still in sync, so this one
            // frame is dropped — unless a call is waiting on the id it carried, which is then told
            // rather than left waiting for a reply that has already come and gone.
            Err(FrameError::InvalidBody { id, message }) => {
                let waiter = id.as_ref().and_then(|id| routes.state().waiting.remove(id));
                if let Some(waiter) = waiter {
                    let _ = waiter.send(Err(ClientError::Frame(FrameError::InvalidBody {
                        id,
                        message,
                    })));
                }
            }
            Err(e) => {
                routes.end(|_| ClientError::Frame(copy_frame_error(&e)));
                return;
            }
        }
    }
}

/// A second [`FrameError`] saying what `error` says, for handing one failure to several waiters.
fn copy_frame_error(error: &FrameError) -> FrameError {
    match error {
        FrameError::Closed => FrameError::Closed,
        FrameError::TooLarge(n) => FrameError::TooLarge(*n),
        FrameError::Malformed(m) => FrameError::Malformed(m.clone()),
        FrameError::InvalidBody { id, message } => FrameError::InvalidBody {
            id: id.clone(),
            message: message.clone(),
        },
        FrameError::Io(e) => FrameError::Io(std::io::Error::new(e.kind(), e.to_string())),
    }
}

impl DuplexClient {
    /// Send one request and wait for its reply, whatever arrives in between.
    ///
    /// # Errors
    ///
    /// [`ClientError::IdInUse`] if another call is waiting on `id`; [`ClientError::Frame`] on a
    /// wire failure, including a connection that has already ended; [`ClientError::Correlation`]
    /// if the app sent a reply to a request nobody made, which ends the connection's routing.
    pub fn call(&self, id: &str, request: &Request) -> Result<Response, ClientError> {
        match &self.reading {
            Reading::Background(routes) => {
                let (waiter, reply) = sync_channel(1);
                {
                    let mut state = routes.state();
                    if state.ended {
                        return Err(FrameError::Closed.into());
                    }
                    if state.waiting.contains_key(id) {
                        return Err(ClientError::IdInUse(id.to_owned()));
                    }
                    // Registered before the request is written, so a reply can never beat it.
                    state.waiting.insert(id.to_owned(), waiter);
                }
                if let Err(e) = self.write(id, request) {
                    routes.state().waiting.remove(id);
                    return Err(e);
                }
                // A closed channel is the reader gone without answering, which `end` rules out;
                // say "closed" rather than panic if that ever stops being true.
                reply
                    .recv()
                    .unwrap_or_else(|_| Err(FrameError::Closed.into()))
            }
            Reading::LockStep { reader, pushes } => {
                // Held from the write to the reply, so lock-step calls take turns whole.
                let mut reader = reader.lock().map_err(|_| out_of_sync())?;
                self.write(id, request)?;
                loop {
                    match frame::read::<_, HostBound>(&mut *reader) {
                        Ok(HostBound::Push(push)) => {
                            let _ = pushes.send(push);
                        }
                        Ok(HostBound::Reply(reply)) if reply.id == id => return Ok(reply.body),
                        Ok(HostBound::Reply(reply)) => {
                            return Err(ClientError::Correlation {
                                got: reply.id,
                                want: id.to_owned(),
                            });
                        }
                        Err(FrameError::InvalidBody { id: got, message })
                            if got.as_deref() == Some(id) =>
                        {
                            return Err(FrameError::InvalidBody { id: got, message }.into());
                        }
                        // In sync, and not this call's: dropped, as the reader thread drops it.
                        Err(FrameError::InvalidBody { .. }) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    }

    fn write(&self, id: &str, request: &Request) -> Result<(), ClientError> {
        let mut writer = self.writer.lock().map_err(|_| out_of_sync())?;
        frame::write(&mut *writer, &Envelope::new(id, request))?;
        Ok(())
    }
}

/// The error for a lock a thread panicked while holding: part of a frame may be on the wire.
fn out_of_sync() -> ClientError {
    ClientError::Frame(FrameError::Io(std::io::Error::other(
        "a caller panicked mid-frame; the connection is no longer in sync",
    )))
}

impl std::fmt::Debug for DuplexClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DuplexClient { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connecting_to_nothing_says_the_app_is_not_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), "nobody-home.sock");
        let err = Client::connect(&endpoint).unwrap_err();
        assert!(
            matches!(err, ClientError::AppNotRunning),
            "the common failure must be legible, not an errno: {err:?}"
        );
        assert!(err.to_string().contains("Open the Kagisecure app"));
    }

    /// A pipe name whose every instance is taken is waited on for a while, not forever.
    ///
    /// Windows only, because only named pipes have the state: a Unix listener's backlog accepts a
    /// second `connect` whether or not anyone calls `accept`. Here the listener's one instance is
    /// connected to `first` and never accepted, so no instance of the name is ever free again —
    /// the shape a stopped listener's leftover connections used to leave behind.
    #[cfg(windows)]
    #[test]
    fn a_pipe_with_no_free_instance_is_given_up_on_rather_than_waited_on_forever() {
        use kagisecure_ipc::connect::PIPE_BUSY_WAIT;

        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), "busy.sock");
        let listener = crate::listener::Listener::bind(&endpoint).expect("bind");
        let first = Client::connect(&endpoint).expect("the one free instance");

        let started = std::time::Instant::now();
        let err = Client::connect(&endpoint).unwrap_err();
        assert!(matches!(err, ClientError::AppNotRunning), "{err:?}");
        let waited = started.elapsed();
        assert!(
            waited >= PIPE_BUSY_WAIT / 2 && waited < PIPE_BUSY_WAIT * 10,
            "waited {waited:?} against a {PIPE_BUSY_WAIT:?} bound"
        );
        drop(first);
        drop(listener);
    }
}
