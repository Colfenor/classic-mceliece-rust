//! Decryption function to turn ciphertext into a ciphertext using the secret key

use crate::{
    benes::{support_gen_with_scratch, SupportGenScratch},
    bm::bm,
    gf::gf_iszero,
    macros::sub,
    params::{COND_BYTES, GFBITS, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
    root::root,
    synd::synd,
    util::load_gf,
};

/// Preallocated decapsulation workspace.
///
/// This holds all large temporary buffers used by Niederreiter decapsulation.
/// Embedded callers can keep a single instance in long-lived memory and reuse
/// it across operations, avoiding large stack allocations per call.
///
/// The support-generation scratch segment inside this workspace is treated as
/// transient memory and scrubbed as part of the decapsulation flow.
#[cfg_attr(docsrs, doc(cfg(feature = "embedded-workspace")))]
pub struct DecapsulationWorkspace {
    /// Expanded ciphertext bytes with trailing zero padding.
    r: [u8; SYS_N / 8],
    /// Goppa polynomial coefficients derived from the secret key.
    g: [u16; SYS_T + 1],
    /// Support set generated from Benes control bits.
    l: [u16; SYS_N],
    /// Computed syndrome.
    s: [u16; SYS_T * 2],
    /// Recomputed syndrome for verification.
    s_cmp: [u16; SYS_T * 2],
    /// Error-locator polynomial.
    locator: [u16; SYS_T + 1],
    /// Roots of the locator polynomial over support values.
    images: [u16; SYS_N],
    /// Scratch storage used internally by support generation.
    ///
    /// This buffer is passed to `support_gen_with_scratch`, which clears it on
    /// entry and scrubs it before return.
    support_scratch: SupportGenScratch,
}

impl DecapsulationWorkspace {
    /// Create a zero-initialized workspace.
    pub const fn new() -> Self {
        Self {
            r: [0u8; SYS_N / 8],
            g: [0u16; SYS_T + 1],
            l: [0u16; SYS_N],
            s: [0u16; SYS_T * 2],
            s_cmp: [0u16; SYS_T * 2],
            locator: [0u16; SYS_T + 1],
            images: [0u16; SYS_N],
            support_scratch: [[0u8; (1 << GFBITS) / 8]; GFBITS],
        }
    }

    /// Overwrite all buffers in-place.
    ///
    /// Called before and after decapsulation to avoid stale sensitive
    /// intermediates persisting in long-lived memory.
    pub fn clear(&mut self) {
        self.r.fill(0);
        self.g.fill(0);
        self.l.fill(0);
        self.s.fill(0);
        self.s_cmp.fill(0);
        self.locator.fill(0);
        self.images.fill(0);
        for row in self.support_scratch.iter_mut() {
            row.fill(0);
        }
    }
}

impl Default for DecapsulationWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Core decapsulation implementation that consumes a caller-provided workspace.
///
/// The workspace's support-generation scratch is used as temporary storage and
/// is wiped by support-generation and by workspace clears at function boundaries.
fn decrypt_with_workspace(
    e: &mut [u8; SYS_N / 8],
    sk: &[u8; IRR_BYTES + COND_BYTES],
    c: &[u8; SYND_BYTES],
    workspace: &mut DecapsulationWorkspace,
) -> u8 {
    // Start from a known clean state even when the caller reuses one
    // long-lived workspace instance.
    workspace.clear();
    let DecapsulationWorkspace {
        r,
        g,
        l,
        s,
        s_cmp,
        locator,
        images,
        support_scratch,
    } = workspace;

    let mut t: u16;
    let mut w: i32 = 0;

    // Expand ciphertext to SYS_N bits by zero-padding bits beyond the
    // syndrome length expected by Niederreiter decoding.
    r[..SYND_BYTES].copy_from_slice(&c[..SYND_BYTES]);
    r[SYND_BYTES..SYS_N / 8].fill(0);

    // Load the Goppa polynomial from secret-key bytes and make it monic.
    for (i, chunk) in sk.chunks(2).take(SYS_T).enumerate() {
        g[i] = load_gf(sub!(chunk, 0, 2));
    }
    g[SYS_T] = 1;

    // Build the support set from Benes control bits using caller-provided
    // scratch to avoid hidden global mutable state.
    support_gen_with_scratch(l, sub!(sk, IRR_BYTES, COND_BYTES), support_scratch);

    // Classic Niederreiter decoding pipeline.
    synd(s, g, l, r);
    bm(locator, s);
    root(images, locator, l);

    e.fill(0);

    // Each zero root corresponds to an error position. Weight is accumulated
    // for the final validity check.
    for i in 0..SYS_N {
        t = gf_iszero(images[i]) & 1;

        e[i / 8] |= (t << (i % 8)) as u8;
        w += t as i32;
    }

    // Recompute syndrome from recovered error vector and compare against the
    // original one. Combined with the exact-weight check this determines
    // whether decoding succeeded.
    synd(s_cmp, g, l, e);

    let mut check = w as u16;
    check ^= SYS_T as u16;

    for i in 0..SYS_T * 2 {
        check |= s[i] ^ s_cmp[i];
    }

    // Map "all checks passed" to 0 and failure to 1 without branches.
    check = check.wrapping_sub(1);
    check >>= 15;

    let result = (check ^ 1) as u8;

    // Clear sensitive intermediates before returning to the caller.
    workspace.clear();
    result
}

/// Niederreiter decryption with the Berlekamp decoder.
///
/// Non-embedded entry point that allocates a workspace on the stack.
#[cfg(not(feature = "embedded-workspace"))]
pub(crate) fn decrypt(
    e: &mut [u8; SYS_N / 8],
    sk: &[u8; IRR_BYTES + COND_BYTES],
    c: &[u8; SYND_BYTES],
) -> u8 {
    let mut workspace = DecapsulationWorkspace::new();
    decrypt_with_workspace(e, sk, c, &mut workspace)
}

/// Niederreiter decryption with caller-managed workspace.
///
/// Embedded callers should use this entry point to reuse a single workspace
/// across invocations and avoid large per-call stack frames.
#[cfg(feature = "embedded-workspace")]
pub(crate) fn decrypt(
    e: &mut [u8; SYS_N / 8],
    sk: &[u8; IRR_BYTES + COND_BYTES],
    c: &[u8; SYND_BYTES],
    workspace: &mut DecapsulationWorkspace,
) -> u8 {
    decrypt_with_workspace(e, sk, c, workspace)
}

#[cfg(test)]
#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
mod tests {
    use super::*;
    use crate::test_utils::TestData;

    #[test]
    fn test_decrypt() {
        let sk = TestData::new().u8vec("mceliece8192128f_sk1"); // TODO: sk has wrong size … IRR_BYTES + COND_BYTES required
        let mut c = TestData::new().u8vec("mceliece8192128f_ct1");
        let expected_error_vector = TestData::new().u8vec("mceliece8192128f_decrypt_errvec");

        let mut actual_error_vector = [0u8; 1 + SYS_N / 8];
        actual_error_vector[0] = 2;

        #[cfg(feature = "embedded-workspace")]
        {
            let mut workspace = DecapsulationWorkspace::new();
            decrypt(
                sub!(mut actual_error_vector, 1, SYS_N / 8),
                sub!(sk, 40, IRR_BYTES + COND_BYTES),
                sub!(mut c, 0, SYND_BYTES),
                &mut workspace,
            );
        }
        #[cfg(not(feature = "embedded-workspace"))]
        {
            decrypt(
                sub!(mut actual_error_vector, 1, SYS_N / 8),
                sub!(sk, 40, IRR_BYTES + COND_BYTES),
                sub!(mut c, 0, SYND_BYTES),
            );
        }

        assert_eq!(
            &actual_error_vector[1..SYS_N / 8],
            &expected_error_vector[1..SYS_N / 8]
        );
    }
}
