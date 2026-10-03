//! The password generator and one-time passwords. ADR-0008 crossing 5, both directions.

use super::{
    KgsBuffer, KgsGeneratorMode, KgsOptBuffer, KgsOptSlice, KgsSlice, KgsStatus, KgsStrengthBucket,
    KgsTotpAlgorithm, KgsWordSeparator, Release, call, free, read, slot,
};
use crate::{FfiResult, GeneratorRecipe, StrengthView, TotpCodeView, TotpParamsView};

/// [`GeneratorRecipe`], going in. Enums are their [`KgsGeneratorMode`] / [`KgsWordSeparator`]
/// tags.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsGeneratorRecipe {
    /// A [`KgsGeneratorMode`] tag.
    pub mode: u32,
    /// Characters mode: how many characters.
    pub length: u32,
    /// Words mode: how many words.
    pub words: u32,
    /// A [`KgsWordSeparator`] tag.
    pub separator: u32,
    /// Characters mode: include `a`-`z`.
    pub lowercase: u8,
    /// Characters mode: include `A`-`Z`.
    pub uppercase: u8,
    /// Characters mode: include `0`-`9`.
    pub digits: u8,
    /// Characters mode: include symbols.
    pub symbols: u8,
    /// Characters mode: leave out look-alikes.
    pub avoid_ambiguous: u8,
    /// Words mode: capitalize each word.
    pub capitalize: u8,
    /// Words mode: append one digit.
    pub include_digit: u8,
}

impl KgsGeneratorRecipe {
    fn to_ffi(self) -> FfiResult<GeneratorRecipe> {
        Ok(GeneratorRecipe {
            mode: KgsGeneratorMode::parse(self.mode)?,
            length: self.length,
            lowercase: self.lowercase != 0,
            uppercase: self.uppercase != 0,
            digits: self.digits != 0,
            symbols: self.symbols != 0,
            avoid_ambiguous: self.avoid_ambiguous != 0,
            words: self.words,
            separator: KgsWordSeparator::parse(self.separator)?,
            capitalize: self.capitalize != 0,
            include_digit: self.include_digit != 0,
        })
    }
}

/// [`crate::GeneratorLimits`]. Plain data: nothing to free.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsGeneratorLimits {
    /// Shortest character-mode password.
    pub min_length: u32,
    /// Longest character-mode password.
    pub max_length: u32,
    /// Fewest words.
    pub min_words: u32,
    /// Most words.
    pub max_words: u32,
    /// How many words the embedded list holds.
    pub wordlist_size: u32,
}

/// [`StrengthView`]. Free with [`kgs_strength_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsStrength {
    /// Estimated entropy in bits.
    pub bits: f64,
    /// A [`KgsStrengthBucket`] tag.
    pub bucket: u32,
    /// The label for that bucket.
    pub label: KgsBuffer,
    /// How full a 0–1 bar should be.
    pub fraction: f64,
}

impl KgsStrength {
    fn new(s: StrengthView) -> Self {
        Self {
            bits: s.bits,
            bucket: KgsStrengthBucket::tag(s.bucket),
            label: KgsBuffer::from_string(s.label),
            fraction: s.fraction,
        }
    }
}

impl Release for KgsStrength {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.label.release() };
    }
}

/// [`TotpParamsView`], going out. Free with [`kgs_totp_params_free`].
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsTotpParams {
    /// A [`KgsTotpAlgorithm`] tag.
    pub algorithm: u32,
    /// 6, 7 or 8.
    pub digits: u8,
    /// Seconds per code.
    pub period: u32,
    /// The service, if the URI named one.
    pub issuer: KgsOptBuffer,
    /// The account, if the URI named one.
    pub account: KgsOptBuffer,
    /// `"GitHub · ada@example.com"`.
    pub caption: KgsOptBuffer,
}

impl KgsTotpParams {
    fn new(p: TotpParamsView) -> Self {
        Self {
            algorithm: KgsTotpAlgorithm::tag(p.algorithm),
            digits: p.digits,
            period: p.period,
            issuer: KgsOptBuffer::from_string(p.issuer),
            account: KgsOptBuffer::from_string(p.account),
            caption: KgsOptBuffer::from_string(p.caption),
        }
    }
}

impl Release for KgsTotpParams {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.issuer.release();
            self.account.release();
            self.caption.release();
        }
    }
}

/// [`TotpParamsView`], going in. `caption` is carried for symmetry and ignored, exactly as the
/// UniFFI function ignores it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsTotpParamsRef {
    /// A [`KgsTotpAlgorithm`] tag.
    pub algorithm: u32,
    /// 6, 7 or 8.
    pub digits: u8,
    /// Seconds per code.
    pub period: u32,
    /// The service.
    pub issuer: KgsOptSlice,
    /// The account.
    pub account: KgsOptSlice,
    /// Ignored.
    pub caption: KgsOptSlice,
}

impl KgsTotpParamsRef {
    /// # Safety
    ///
    /// Every present slice must satisfy [`KgsSlice`]'s contract.
    unsafe fn to_ffi(self) -> FfiResult<TotpParamsView> {
        // SAFETY: forwarded to the caller.
        unsafe {
            Ok(TotpParamsView {
                algorithm: KgsTotpAlgorithm::parse(self.algorithm)?,
                digits: self.digits,
                period: self.period,
                issuer: self.issuer.string()?,
                account: self.account.string()?,
                caption: self.caption.string()?,
            })
        }
    }
}

/// [`TotpCodeView`]. Free with [`kgs_totp_code_free`].
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsTotpCode {
    /// The code. ADR-0008 crossing 5, outbound.
    pub code: KgsBuffer,
    /// Seconds left in this code's window.
    pub seconds_remaining: u32,
    /// The field's parameters.
    pub params: KgsTotpParams,
}

impl KgsTotpCode {
    pub(crate) fn new(c: TotpCodeView) -> Self {
        Self {
            code: KgsBuffer::from_string(c.code),
            seconds_remaining: c.seconds_remaining,
            params: KgsTotpParams::new(c.params),
        }
    }
}

impl Release for KgsTotpCode {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.code.release();
            self.params.release();
        }
    }
}

// -------------------------------------------------------------------------------------------
// Functions
// -------------------------------------------------------------------------------------------

/// [`crate::generator_limits`].
///
/// # Safety
///
/// `out` and `error` as in the module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_generator_limits(
    out: *mut KgsGeneratorLimits,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let l = crate::generator_limits();
            out.write(KgsGeneratorLimits {
                min_length: l.min_length,
                max_length: l.max_length,
                min_words: l.min_words,
                max_words: l.max_words,
                wordlist_size: l.wordlist_size,
            });
            Ok(())
        })
    }
}

/// [`crate::generate_password`]. ADR-0008 crossing 5, outbound.
///
/// # Safety
///
/// `recipe` must be valid for a read; `out` and `error` as in the module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_generate_password(
    recipe: *const KgsGeneratorRecipe,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let recipe = read(recipe, "recipe")?.to_ffi()?;
            out.write(KgsBuffer::from_string(crate::generate_password(recipe)?));
            Ok(())
        })
    }
}

/// [`crate::recipe_strength`].
///
/// # Safety
///
/// As [`kgs_generate_password`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_recipe_strength(
    recipe: *const KgsGeneratorRecipe,
    out: *mut KgsStrength,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let recipe = read(recipe, "recipe")?.to_ffi()?;
            out.write(KgsStrength::new(crate::recipe_strength(recipe)));
            Ok(())
        })
    }
}

/// [`crate::password_strength`]. `password` is a secret going in; Rust's copy dies with the call.
///
/// # Safety
///
/// `password` must satisfy [`KgsSlice`]'s contract; `out` and `error` as in the module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_password_strength(
    password: KgsSlice,
    out: *mut KgsStrength,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsStrength::new(crate::password_strength(
                password.string()?,
            )));
            Ok(())
        })
    }
}

/// [`crate::totp_describe`]. `uri` carries the seed.
///
/// # Safety
///
/// As [`kgs_password_strength`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_describe(
    uri: KgsSlice,
    out: *mut KgsTotpParams,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsTotpParams::new(crate::totp_describe(uri.string()?)?));
            Ok(())
        })
    }
}

/// [`crate::totp_preview`]. ADR-0008 crossing 5, both ways.
///
/// # Safety
///
/// As [`kgs_password_strength`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_preview(
    uri: KgsSlice,
    at: u64,
    out: *mut KgsTotpCode,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsTotpCode::new(crate::totp_preview(uri.string()?, at)?));
            Ok(())
        })
    }
}

/// [`crate::totp_uri_from_parts`]. The seed goes in and the URI — which carries it — comes out.
///
/// # Safety
///
/// `params` must be valid for a read and its slices must satisfy [`KgsSlice`]'s contract;
/// `secret_base32`, `out` and `error` as in the module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_uri_from_parts(
    secret_base32: KgsSlice,
    params: *const KgsTotpParamsRef,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let params = read(params, "TOTP parameters")?.to_ffi()?;
            let uri = crate::totp_uri_from_parts(secret_base32.string()?, params)?;
            out.write(KgsBuffer::from_string(uri));
            Ok(())
        })
    }
}

/// [`crate::totp_uri_is_valid`]. `out` is 0 or 1.
///
/// # Safety
///
/// As [`kgs_password_strength`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_uri_is_valid(
    uri: KgsSlice,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(crate::totp_uri_is_valid(uri.string()?)));
            Ok(())
        })
    }
}

/// Free a [`KgsStrength`].
///
/// # Safety
///
/// `strength` must be null, or point to a record this library wrote (or a zeroed one), not
/// modified since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_strength_free(strength: *mut KgsStrength) {
    // SAFETY: forwarded to the caller.
    unsafe { free(strength) }
}

/// Free a [`KgsTotpParams`].
///
/// # Safety
///
/// As [`kgs_strength_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_params_free(params: *mut KgsTotpParams) {
    // SAFETY: forwarded to the caller.
    unsafe { free(params) }
}

/// Zeroize and free a [`KgsTotpCode`].
///
/// # Safety
///
/// As [`kgs_strength_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_code_free(code: *mut KgsTotpCode) {
    // SAFETY: forwarded to the caller.
    unsafe { free(code) }
}
