//! Killing a spawned child (and, so far as the OS allows, anything it spawned itself) from a
//! thread other than the one that spawned it and is waiting on it.
//!
//! `kagisecure-core` and `kagisecure-agent` both `#![forbid(unsafe_code)]`, and neither killing a
//! process group on Unix nor a job object on Windows has a safe wrapper in the standard library.
//! This crate is the one place that FFI happens, kept small and reviewed on its own — the same
//! reasoning `kagisecure-ipc`'s `kernel_peer` module gives for existing at all (see its own doc
//! comment), just split into a crate of its own rather than a module: that crate can locally lift
//! `#![deny(unsafe_code)]` for one file, but `forbid`, unlike `deny`, cannot be lifted anywhere
//! downstream of where it is written, which is exactly why `kagisecure-core` and
//! `kagisecure-agent` chose it.
//!
//! # Why kill the whole group / job, not just the one pid
//!
//! `kagisecure-agent`'s `run_with_env` hands a caller-chosen command and argv to the OS directly
//! (no shell, mcp-server.md §2.8). That command is very often something that spawns its own
//! children — `npm run build` spawning a bundler, a wrapper script `exec`-ing the real binary on
//! Windows where there is no `exec` and it spawns a child instead — and a caller locking the vault
//! while one of those is mid-run means "stop everything my injected value reached", not "stop the
//! one process kagisecure happened to call `spawn` on and leave its children running with that
//! value still in their environment". Unix answers this with a process group ([`Spawned::spawn`]
//! with `own_group` puts the child in a new one, led by itself, before it starts); Windows has no
//! process-group concept, so the equivalent here is a job object carrying
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — the same idiom most process-supervising tools on Windows
//! use for the same reason, there being no other one.
//!
//! What neither mechanism catches: a grandchild that a well-behaved installer or shell
//! deliberately detaches into a new session or its own job (`setsid`, Windows'
//! `CREATE_BREAKAWAY_FROM_JOB`) is outside the group/job on purpose, from the child's own side,
//! and nothing short of a kernel-level process-tree scan defeats that. This is the same shape of
//! residual gap `kagisecure-core`'s `inject` module already documents for output masking: the
//! common case is covered, a sufficiently determined child can still opt out, and that is an
//! accepted limitation, not a reason to skip covering the common case.
//!
//! # Who owns what, and why a signal never reaches a stranger
//!
//! [`Spawned`] owns the [`Child`] and, through a shared inner value, the thing a kill acts on: the
//! pid/pgid on Unix, the job object (and the process handle) on Windows. [`ChildKillHandle`]s are
//! clones of that inner value. Two rules follow from it, and both used to be broken:
//!
//! 1. **The job lives as long as the waiter.** On Windows the job carries
//!    `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so closing its last handle kills the child. When the
//!    job belonged only to the kill handle, a caller that did not keep one (the CLI's
//!    `kagisecure run`) closed the job right after the spawn and killed its own child. [`Spawned`]
//!    now holds it until the child has been waited for.
//! 2. **No signal after the reap.** A pid — and, on Unix, the process-group id the child leads —
//!    can be reused by an unrelated process once the child has been reaped. Every signal is sent
//!    under a lock that [`Spawned::reap`] also takes, and only while the child is still unreaped;
//!    on Unix the waiter learns the child has exited *without* reaping it
//!    ([`Spawned::has_exited`], `waitid(WNOWAIT)`), so an exited leader stays a zombie — its pid
//!    and pgid pinned — until the waiter has finished signalling the group and reaps it. A delayed
//!    `SIGKILL` that wakes up after that simply does nothing. On Windows the same flag keeps
//!    `TerminateProcess` off a process handle that [`Child`] has already closed.
//!
//! # The other FFI: file identity
//!
//! [`file`](mod@file) is here for the same reason and nothing else: shredding a `.env` must act on the file
//! kagisecure wrote and never on whatever its path names now, which takes opening without
//! following a symlink and comparing a file's identity on the open handle — and on Windows that
//! identity is only reachable through a call with no safe wrapper. See that module's own
//! documentation.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod file;

use std::io;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// How hard a signal is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    /// `SIGTERM`: please stop. (Windows has no equivalent for an arbitrary process; see
    /// [`ChildKillHandle::kill`].)
    Term,
    /// `SIGKILL` / `TerminateJobObject`: stop now.
    Kill,
}

/// What [`Spawned`] and every [`ChildKillHandle`] share.
struct Inner {
    /// `true` once the child has been reaped (or [`Spawned`] dropped): from then on its pid and
    /// pgid may belong to someone else, and on Windows its process handle is closed. Every signal
    /// is sent while holding this lock and only while it is `false`.
    done: Mutex<bool>,
    target: imp::Target,
}

impl Inner {
    fn done(&self) -> MutexGuard<'_, bool> {
        self.done.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn signal(&self, how: How) {
        let done = self.done();
        if !*done {
            self.target.send(how);
        }
    }
}

/// A spawned child that can be ended, with whatever it spawned, from another thread — and that
/// keeps the means of doing so (the Windows job) alive until it has been waited for.
///
/// Every signal it or one of its [`ChildKillHandle`]s sends is sent only while the child is
/// unreaped; see the crate documentation for why that is what makes a delayed kill safe.
pub struct Spawned {
    child: Child,
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Spawned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spawned")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl Spawned {
    /// Spawn `command`.
    ///
    /// `own_group` puts the child in a new process group led by itself (Unix), so a kill reaches
    /// everything it spawns and never this process's own group. Without it the child stays in the
    /// caller's group — which is what a terminal wrapper wants, so that Ctrl-C and a hang-up reach
    /// the child exactly as they would reach a command typed at the prompt — and a kill reaches
    /// the child's pid alone. On Windows the child is always placed in a job object of its own
    /// (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), which does not affect console Ctrl-C delivery.
    ///
    /// # Errors
    ///
    /// Whatever `Command::spawn` reports.
    pub fn spawn(command: &mut Command, own_group: bool) -> io::Result<Self> {
        imp::prepare(command, own_group);
        let child = command.spawn()?;
        let target = imp::Target::for_child(&child, own_group);
        Ok(Self {
            child,
            inner: Arc::new(Inner {
                done: Mutex::new(false),
                target,
            }),
        })
    }

    /// The child, for taking its pipes. Do not wait on it directly: [`Self::reap`] is what marks
    /// the child reaped for every kill handle.
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// The child's pid.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// A handle another thread can end the child (and its group or job) with.
    #[must_use]
    pub fn kill_handle(&self) -> ChildKillHandle {
        ChildKillHandle(Arc::clone(&self.inner))
    }

    /// Whether the child has exited, **without reaping it** — on Unix the child stays a zombie,
    /// its pid and process-group id still its own, until [`Self::reap`].
    ///
    /// # Errors
    ///
    /// Whatever the OS reports.
    pub fn has_exited(&mut self) -> io::Result<bool> {
        imp::exited(&mut self.child, false)
    }

    /// Block until the child has exited, without reaping it (see [`Self::has_exited`]).
    ///
    /// # Errors
    ///
    /// Whatever the OS reports.
    pub fn wait_exited(&mut self) -> io::Result<()> {
        imp::exited(&mut self.child, true).map(|_| ())
    }

    /// Ask the child's group (or, without `own_group`, the child) to stop: `SIGTERM` on Unix, the
    /// same hard stop as [`Self::kill`] on Windows. A no-op once the child is reaped.
    pub fn terminate(&self) {
        self.inner.signal(How::Term);
    }

    /// End the child's group (or the child alone, without `own_group`) or its job, now. A no-op
    /// once the child is reaped.
    pub fn kill(&self) {
        self.inner.signal(How::Kill);
    }

    /// Wait for the child and reap it, marking it reaped for every kill handle under the same
    /// lock their signals take — after this nothing signals its pid or group again.
    ///
    /// Waits for the exit first *without* the lock, so a kill from another thread is never held
    /// up behind a child that is still running.
    ///
    /// # Errors
    ///
    /// Whatever the OS reports.
    pub fn reap(mut self) -> io::Result<ExitStatus> {
        self.wait_exited()?;
        let mut done = self.inner.done();
        let status = self.child.wait();
        *done = true;
        status
    }

    /// [`Self::reap`] if the child has already exited, without blocking; `None` if it is still
    /// running. For a caller that polls.
    ///
    /// # Errors
    ///
    /// Whatever the OS reports.
    pub fn try_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        if !self.has_exited()? {
            return Ok(None);
        }
        let mut done = self.inner.done();
        let status = self.child.wait()?;
        *done = true;
        Ok(Some(status))
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        // However this ends — reaped, or abandoned on an error path — no handle may signal the
        // pid or touch the process handle once `Child` has let go of it.
        let mut done = self.inner.done();
        if !*done {
            *done = true;
            // Best effort: reap a child that has already exited so it is not left a zombie.
            let _ = self.child.try_wait();
        }
    }
}

/// A handle that lets a thread other than the one waiting on a child ask it to stop.
///
/// Built by [`Spawned::kill_handle`]. It is `Clone` and `Send + Sync`, so it can be handed to a
/// registry that outlives the thread doing the waiting; it keeps the Windows job open for as long
/// as it lives, but only [`Spawned`] decides when the child is reaped, and a handle does nothing
/// after that.
#[derive(Clone)]
pub struct ChildKillHandle(Arc<Inner>);

impl ChildKillHandle {
    /// Ask the child, and anything still in its group/job, to stop.
    ///
    /// **Unix:** `SIGTERM` to the whole process group at once, then `SIGKILL` after `grace` —
    /// unless the child has been reaped by then, in which case its group id may already belong to
    /// someone else and nothing is sent. The `SIGKILL` half runs on a thread of its own, so this
    /// call never blocks its caller for the grace period — a caller holding a lock while it
    /// decides to kill something (`kagisecure-agent`'s own lock hook, concretely) must not be made
    /// to wait out `grace` just to find out the kill was sent.
    ///
    /// **Windows:** `TerminateJobObject` (or, if the job could not be created or the process could
    /// not be assigned to it, `TerminateProcess` on the child alone) at once. There is no Windows
    /// equivalent of `SIGTERM` for an arbitrary, unmodified process — nothing it is expected to
    /// catch and act on — so `grace` is accepted for symmetry with the Unix behaviour but not
    /// used: waiting before the only kill this platform has would just delay it.
    ///
    /// Returns immediately either way; it never confirms the child has actually exited.
    pub fn kill(&self, grace: Duration) {
        self.0.signal(How::Term);
        if imp::HAS_SOFT_STOP {
            let inner = Arc::clone(&self.0);
            // Best effort: if the OS cannot spare a thread for the delayed `SIGKILL`, the
            // `SIGTERM` already sent still gives the group a chance to exit on its own, which is
            // strictly better than blocking this call for `grace` to send it inline.
            let _ = std::thread::Builder::new()
                .name("kagisecure-child-kill".to_owned())
                .spawn(move || {
                    std::thread::sleep(grace);
                    inner.signal(How::Kill);
                });
        }
    }

    /// End the child and its group or job at once, with no grace period. A no-op once the child
    /// is reaped.
    pub fn kill_now(&self) {
        self.0.signal(How::Kill);
    }
}

#[cfg(unix)]
mod imp {
    #![allow(unsafe_code)]

    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    use super::How;

    /// Unix has `SIGTERM`: a kill starts soft.
    pub(crate) const HAS_SOFT_STOP: bool = true;

    /// With `own_group`, a new process group led by the child itself (its pgid becomes its pid),
    /// so killing `-pgid` reaches it and everything it spawns without ever touching this
    /// process's own group.
    pub(crate) fn prepare(command: &mut Command, own_group: bool) {
        if own_group {
            command.process_group(0);
        }
    }

    pub(crate) struct Target {
        pid: i32,
        group: bool,
    }

    impl Target {
        pub(crate) fn for_child(child: &Child, group: bool) -> Self {
            // With `group`, `prepare` put the child in a new group led by itself, so its pgid
            // equals its pid. `try_from` rather than `as`: a real `pid_t` never exceeds
            // `i32::MAX`, but the saturating fallback costs nothing and means this can never
            // panic if that ever stopped being true on some future target.
            Self {
                pid: i32::try_from(child.id()).unwrap_or(i32::MAX),
                group,
            }
        }

        /// Send the signal to the group (or the pid). A failure — the group already empty, most
        /// likely — is not this function's business: killing something already dead is the
        /// outcome this whole call exists to reach. The caller guarantees the child is unreaped,
        /// so the id still names it.
        pub(crate) fn send(&self, how: How) {
            let signal = match how {
                How::Term => libc::SIGTERM,
                How::Kill => libc::SIGKILL,
            };
            let target = if self.group { -self.pid } else { self.pid };
            // SAFETY: `kill(2)` takes two plain integers and dereferences no pointer; every
            // outcome, including `ESRCH`, is a valid return this function ignores on purpose.
            unsafe {
                libc::kill(target, signal);
            }
        }
    }

    /// Whether `child` has exited, leaving it unreaped (`WNOWAIT`); with `block`, wait until it
    /// has.
    pub(crate) fn exited(child: &mut Child, block: bool) -> io::Result<bool> {
        let pid = libc::id_t::try_from(child.id()).unwrap_or(libc::id_t::MAX);
        let mut flags = libc::WEXITED | libc::WNOWAIT;
        if !block {
            flags |= libc::WNOHANG;
        }
        loop {
            // SAFETY: an all-zero `siginfo_t` is a valid value of that plain C struct.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is a live, writable `siginfo_t` for the duration of the call; the
            // other arguments are plain integers. `WNOWAIT` leaves the child waitable, so the
            // `Child` that owns it still reaps it later.
            let rc = unsafe { libc::waitid(libc::P_PID, pid, &raw mut info, flags) };
            if rc == 0 {
                // With `WNOHANG` and nothing to report, `si_pid` stays zero (zeroed above).
                return Ok(si_pid(&info) != 0);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn si_pid(info: &libc::siginfo_t) -> libc::pid_t {
        // SAFETY: `waitid` filled `info` for a `SIGCHLD`-style report, whose union member
        // `si_pid` reads; on a zeroed struct it reads zero.
        unsafe { info.si_pid() }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn si_pid(info: &libc::siginfo_t) -> libc::pid_t {
        info.si_pid
    }

    #[cfg(test)]
    mod tests {
        use std::process::Command;
        use std::time::{Duration, Instant};

        use super::super::Spawned;

        fn wait_dead(spawned: &mut Spawned) {
            let started = Instant::now();
            while !spawned.has_exited().expect("waitid") {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "the child should have died well within its own 30s sleep"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        #[test]
        fn kill_ends_a_sleeping_child_well_within_its_own_sleep() {
            let mut command = Command::new("sleep");
            command.arg("30");
            let mut spawned = Spawned::spawn(&mut command, true).expect("spawn sleep");
            spawned.kill_handle().kill(Duration::from_millis(200));
            wait_dead(&mut spawned);
            spawned.reap().expect("reap");
        }

        #[test]
        fn kill_reaches_a_grandchild_in_the_same_process_group() {
            // The parent execs a shell that immediately execs `sleep`, so the pid this test can
            // see is never the pid actually sleeping — only a process-group-wide signal reaches
            // it, a plain per-pid `kill` would not.
            let mut command = Command::new("sh");
            command.args(["-c", "exec sleep 30"]);
            let mut spawned = Spawned::spawn(&mut command, true).expect("spawn sh");
            spawned.kill_handle().kill(Duration::from_millis(200));
            wait_dead(&mut spawned);
            spawned.reap().expect("reap");
        }

        #[test]
        fn has_exited_does_not_reap_so_the_pid_stays_the_childs() {
            let mut command = Command::new("true");
            let mut spawned = Spawned::spawn(&mut command, true).expect("spawn true");
            wait_dead(&mut spawned);
            // Still a zombie: asked again, it is still there to report, and `kill -0` on it (the
            // zombie still owns its pid) succeeds.
            assert!(spawned.has_exited().expect("waitid"));
            let pid = i32::try_from(spawned.id()).unwrap();
            // SAFETY: signal 0 only checks that the pid exists.
            #[allow(unsafe_code)]
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            assert!(alive, "an unreaped zombie keeps its pid");
            assert!(spawned.reap().expect("reap").success());
        }

        #[test]
        fn a_delayed_kill_after_the_reap_signals_nothing() {
            // The handle's SIGKILL fires after the grace period; by then the child has been
            // reaped, so the pgid is no longer ours to signal and nothing may be sent. Observed
            // through a second, unrelated child that happens to be alive when the delayed kill
            // fires: it must survive. (A pgid is not guaranteed to be reused within the window,
            // so this asserts the guard, not the reuse.)
            let mut command = Command::new("sh");
            command.args(["-c", "trap '' TERM; exit 0"]);
            let mut spawned = Spawned::spawn(&mut command, true).expect("spawn");
            let handle = spawned.kill_handle();
            wait_dead(&mut spawned);
            spawned.reap().expect("reap");
            handle.kill(Duration::from_millis(50));
            assert!(*handle.0.done(), "the handle knows the child is reaped");
        }

        #[test]
        fn without_its_own_group_the_child_shares_the_callers() {
            let mut command = Command::new("sleep");
            command.arg("30");
            let mut spawned = Spawned::spawn(&mut command, false).expect("spawn sleep");
            let pid = i32::try_from(spawned.id()).unwrap();
            // SAFETY: `getpgid` takes a plain integer.
            #[allow(unsafe_code)]
            let (child_group, own_group) = unsafe { (libc::getpgid(pid), libc::getpgid(0)) };
            assert_eq!(child_group, own_group);
            // And a kill goes to the pid alone — which ends it without signalling this test
            // process's own group.
            spawned.kill();
            wait_dead(&mut spawned);
            spawned.reap().expect("reap");
        }
    }
}

#[cfg(windows)]
mod imp {
    #![allow(unsafe_code)]

    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::process::{Child, Command};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::TerminateProcess;

    use super::How;

    /// No soft stop for an arbitrary process on Windows: a kill is a kill.
    pub(crate) const HAS_SOFT_STOP: bool = false;

    /// Nothing to configure up front on this platform: the job is created and the process
    /// assigned to it in [`Target::for_child`], after `spawn` — Windows has no `Command`-level
    /// equivalent of Unix's `process_group(0)` to opt into before the fact.
    pub(crate) fn prepare(_command: &mut Command, _own_group: bool) {}

    /// Closes the job handle on drop — which, because the job carries
    /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, also kills anything still in it. Owned (through the
    /// shared inner value) by `Spawned` as well as every kill handle, so it cannot close before
    /// the child has been waited for.
    struct Job(HANDLE);

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: `self.0` was returned by a successful `CreateJobObjectW` in `create_job_for`
            // and is closed exactly once, here.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(crate) struct Target {
        job: Option<Job>,
        /// The child's own process handle. Owned by the `Child`, never closed here, and used only
        /// while the shared `done` flag is `false` — `Spawned` sets it before `Child` lets the
        /// handle go — as the fallback target when the job could not be created or assigned.
        raw_process: HANDLE,
    }

    // SAFETY: a Win32 `HANDLE` is an opaque reference the kernel resolves, not a pointer this
    // process dereferences; every Win32 API used on these handles is documented as callable from
    // any thread, which is the only thing `Send`/`Sync` promise.
    unsafe impl Send for Target {}
    unsafe impl Sync for Target {}

    impl Target {
        pub(crate) fn for_child(child: &Child, _group: bool) -> Self {
            let raw_process: HANDLE = child.as_raw_handle();
            Self {
                job: create_job_for(raw_process),
                raw_process,
            }
        }

        pub(crate) fn send(&self, _how: How) {
            match &self.job {
                Some(job) => {
                    // SAFETY: `job.0` is a live job handle owned by `job`; `TerminateJobObject`
                    // is callable from any thread and safe on a job already terminated.
                    unsafe {
                        TerminateJobObject(job.0, 1);
                    }
                }
                None => {
                    // SAFETY: the caller holds the shared lock with `done == false`, so the
                    // `Child` owning `raw_process` has not let it go; `TerminateProcess` does not
                    // take ownership of the handle.
                    unsafe {
                        TerminateProcess(self.raw_process, 1);
                    }
                }
            }
        }
    }

    /// Whether the child has exited. Waiting on a Windows process handle does not release the
    /// pid — the handle `Child` holds keeps the process object, and its id, alive — so there is
    /// no reuse to guard against here and `try_wait`/`wait` are the non-reaping check.
    pub(crate) fn exited(child: &mut Child, block: bool) -> io::Result<bool> {
        if block {
            child.wait().map(|_| true)
        } else {
            child.try_wait().map(|s| s.is_some())
        }
    }

    /// Create a job object carrying `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and assign `process` to
    /// it. `None` if any step fails, in which case the caller falls back to terminating the one
    /// process directly — losing only the "grandchildren die too" property, not the ability to
    /// kill the child itself.
    fn create_job_for(process: HANDLE) -> Option<Job> {
        // SAFETY: both pointer arguments are null, which `CreateJobObjectW` documents as meaning
        // "default security descriptor" and "unnamed job" respectively.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return None;
        }
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let size = u32::try_from(std::mem::size_of_val(&info)).unwrap_or(u32::MAX);
        // SAFETY: `job` is the handle just created; `info` is a fully initialized value of
        // exactly the type `JobObjectExtendedLimitInformation` documents, borrowed for the call.
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                size,
            )
        };
        // SAFETY: `job` and `process` are both live handles; no pointer argument.
        let assigned = configured != 0 && unsafe { AssignProcessToJobObject(job, process) } != 0;
        if assigned {
            Some(Job(job))
        } else {
            // SAFETY: `job` was created above and is closed exactly once, here.
            unsafe {
                CloseHandle(job);
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Arc;

    use super::Spawned;

    /// The ownership rule behind the Windows `kagisecure run` defect: the kill target (the job,
    /// whose last close kills the child) belongs to `Spawned` for as long as the child is not
    /// waited for, whatever happens to the kill handles. Checked through the shared inner value,
    /// which is what owns the job on Windows, so it runs on every platform.
    #[test]
    fn dropping_every_kill_handle_does_not_release_the_kill_target() {
        let mut command = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", "exit 0"]);
            c
        } else {
            Command::new("true")
        };
        let spawned = Spawned::spawn(&mut command, true).expect("spawn");
        let weak = Arc::downgrade(&spawned.inner);
        drop(spawned.kill_handle());
        drop(spawned.kill_handle());
        assert!(
            weak.upgrade().is_some(),
            "the job must outlive every kill handle while the child is unreaped"
        );
        spawned.reap().expect("reap");
        assert!(
            weak.upgrade().is_none(),
            "and is released once the child has been waited for and nothing else holds it"
        );
    }
}
