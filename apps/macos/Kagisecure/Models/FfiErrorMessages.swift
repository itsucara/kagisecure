import KagisecureFFI

/// The sentence every alert in the app shows for an `FfiError`.
///
/// Every payload here is safe user-facing text — a path, a missing-thing description, a reason —
/// never a secret value (see `kagisecure-ffi`'s own doc comment on `FfiError`), so returning it
/// verbatim, or wrapping one short sentence around it, is always safe.
///
/// Kept in one place because five models (`AppModel`, `VaultStore`, `AgentService`,
/// `ExtensionService`, `ImportModel`) used to carry an identical `switch` over every case by hand
/// — which meant a variant added on the Rust side had to be remembered in five places to keep the
/// build exhaustive. Step 4 added three (`Busy`, `Diverged`, `ItemChangedElsewhere`); this is the
/// only place that needed to change.
func ffiErrorMessage(_ error: FfiError) -> String {
    switch error {
    case .WrongCredential:
        return String(localized: "That did not unlock the vault.")
    case .NotFound(let message), .AlreadyExists(let message), .NoSuchSlot(let message),
        .NotPresent(let message), .Invalid(let message), .Io(let message):
        return message
    case .Busy:
        return String(localized: "Another kagisecure process is using the vault right now. Try again in a moment.")
    case .Diverged:
        // The full two-choice recovery flow lives in `VaultStore.conflictKind` /
        // `RootView`'s conflict alert; this text is the fallback for the rarer paths (Touch ID
        // enrolment, a direct throw a view has not wired to that alert) that only show a plain
        // message.
        return String(localized: "The vault file changed outside kagisecure. Lock and reopen it to continue.")
    case .ItemChangedElsewhere:
        return String(localized: "This item was changed elsewhere — reload.")
    // ADR-0038: the presence-gated release calls (`releaseField`, `releaseTotp`, `releaseNotes`)
    // and a session after `lock()`. `VaultStore.attemptRelease` does not show an alert for a
    // cancelled prompt, a lock or an ended release — each leaves the screen as it was, which is
    // the whole answer — so these sentences are for the rest.
    case .VaultLocked:
        return String(localized: "The vault is locked.")
    case .NoPresenceGate, .PresenceUnavailable:
        return String(localized: "Kagisecure could not confirm it is you, so nothing was shown or copied.")
    case .PresenceCancelled:
        return String(localized: "Not confirmed, so nothing was shown or copied.")
    case .PresenceBusy:
        return String(localized: "Another confirmation is already in progress. Finish or cancel it first.")
    case .ReleaseEnded:
        return String(localized: "That value is hidden again. Ask for it again to see it.")
    }
}

/// The same mapping, for a plain `Error` that might or might not be an `FfiError` — what every
/// call site actually has after a `catch`.
///
/// Named unlike any of the five `message(for:)` members that call it: a member function shadows a
/// free function of the same base name for every unqualified call inside that type, regardless of
/// argument labels, so `message(for:)` calling something also based-named `message` would resolve
/// to itself and fail to compile with a confusing label mismatch instead of calling this.
func describeAnyError(_ error: Error) -> String {
    (error as? FfiError).map(ffiErrorMessage) ?? error.localizedDescription
}
