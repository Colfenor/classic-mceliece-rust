//! Global paramaters for the different Classic McEliece variants

use std::error;
use std::fmt;
use crate::randombytes::RNGState;
use crate::api;

type R = Result<(), Box<dyn error::Error>>;

#[derive(Debug)]
struct UnknownVariant(String);

impl error::Error for UnknownVariant {}

impl fmt::Display for UnknownVariant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unknown Classic McEliece variant: '{}'", self.0)
    }
}

pub struct ClassicMcEliece<'t, const GFBITS: usize, const SYS_N: usize, const SYS_T: usize>{
    name: &'t str,
}

impl<'t, const GFBITS: usize, const SYS_N: usize, const SYS_T: usize> ClassicMcEliece<'t, GFBITS, SYS_N, SYS_T> {
    const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
    const IRR_BYTES: usize = SYS_T * 2;
    const PK_NROWS: usize = SYS_T * GFBITS;
    const PK_NCOLS: usize = SYS_N - PK_NROWS;
    const PK_ROW_BYTES: usize = (PK_NCOLS + 7) / 8;
    const SYND_BYTES: usize = (PK_NROWS + 7) / 8;
    const GFMASK: usize = (1 << GFBITS) - 1;

    pub fn mceliece348864() -> ClassicMcEliece::<'static, 12, 3488, 64> {
        ClassicMcEliece::<12, 3488, 64>{ name: "mceliece348864" }
    }

    pub fn mceliece348864f() -> ClassicMcEliece::<'static, 12, 3488, 64> {
        ClassicMcEliece::<12, 3488, 64>{ name: "mceliece348864f" }
    }

    pub fn mceliece460896() -> ClassicMcEliece::<'static, 13, 4608, 96> {
        ClassicMcEliece::<13, 4608, 96>{ name: "mceliece460896" }
    }

    pub fn mceliece460896f() -> ClassicMcEliece::<'static, 13, 4608, 96> {
        ClassicMcEliece::<13, 4608, 96>{ name: "mceliece460896f" }
    }

    pub fn mceliece6688128() -> ClassicMcEliece::<'static, 13, 6688, 128> {
        ClassicMcEliece::<13, 6688, 128>{ name: "mceliece6688128" }
    }

    pub fn mceliece6688128f() -> ClassicMcEliece::<'static, 13, 6688, 128> {
        ClassicMcEliece::<13, 6688, 128>{ name: "mceliece6688128f" }
    }

    pub fn mceliece6960119() -> ClassicMcEliece::<'static, 13, 6960, 119> {
        ClassicMcEliece::<13, 6960, 119>{ name: "mceliece6960119" }
    }

    pub fn mceliece6960119f() -> ClassicMcEliece::<'static, 13, 6960, 119> {
        ClassicMcEliece::<13, 6960, 119>{ name: "mceliece6960119f" }
    }

    pub fn mceliece8192128() -> ClassicMcEliece::<'static, 13, 8192, 128> {
        ClassicMcEliece::<13, 8192, 128>{ name: "mceliece8192128" }
    }

    pub fn mceliece8192128f() -> ClassicMcEliece::<'static, 13, 8192, 128> {
        ClassicMcEliece::<13, 8192, 128>{ name: "mceliece8192128f" }
    }

    pub fn crypto_kem_enc(&self, c: &mut [u8], key: &mut [u8], pk: &[u8], rng: &mut impl RNGState) -> R {
        Ok(())
    }

    pub fn crypto_kem_dec(&self, key: &mut [u8], c: &[u8], sk: &[u8]) -> R {
        Ok(())
    }

    pub fn crypto_kem_keypair(&self, pk: &mut [u8], sk: &mut [u8], rng: &mut impl RNGState) -> R {
        Ok(())
    }
}

#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub const GFBITS: usize = 12;
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub const SYS_N: usize = 3488;
#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub const SYS_T: usize = 64;


#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
pub const GFBITS: usize = 13;
#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
pub const SYS_N: usize = 4608;
#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
pub const SYS_T: usize = 96;


#[cfg(any(feature = "mceliece6688128", feature = "mceliece6688128f"))]
pub const GFBITS: usize = 13;
#[cfg(any(feature = "mceliece6688128", feature = "mceliece6688128f"))]
pub const SYS_N: usize = 6688;
#[cfg(any(feature = "mceliece6688128", feature = "mceliece6688128f"))]
pub const SYS_T: usize = 128;


#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
pub const GFBITS: usize = 13;
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
pub const SYS_N: usize = 6960;
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
pub const SYS_T: usize = 119;


#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
pub const GFBITS: usize = 13;
#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
pub const SYS_N: usize = 8192;
#[cfg(any(feature = "mceliece8192128", feature = "mceliece8192128f"))]
pub const SYS_T: usize = 128;


pub const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
pub const IRR_BYTES: usize = SYS_T * 2;
pub const PK_NROWS: usize = SYS_T * GFBITS;
pub const PK_NCOLS: usize = SYS_N - PK_NROWS;
pub const PK_ROW_BYTES: usize = (PK_NCOLS + 7) / 8;
pub const SYND_BYTES: usize = (PK_NROWS + 7) / 8;
pub const GFMASK: usize = (1 << GFBITS) - 1;
