pub(crate) mod benes;
pub(crate) mod crypto_hash;
pub(crate) mod int32_sort;
pub(crate) mod transpose;
pub(crate) mod uint64_sort;

#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) mod gf12;
#[cfg(not(any(feature = "mceliece348864", feature = "mceliece348864f")))]
pub(crate) mod gf13;

#[cfg(any(feature = "mceliece348864", feature = "mceliece348864f"))]
pub(crate) mod internals348864 {
    pub(crate) mod benes;
    pub(crate) mod bm;
    pub(crate) mod controlbits;
    pub(crate) mod decrypt;
    pub(crate) mod encrypt;
    pub(crate) mod gf_mul;
    pub(crate) mod params;
    pub(crate) mod root;
    pub(crate) mod sk_gen;
    pub(crate) mod synd;
}

#[cfg(any(feature = "mceliece460896", feature = "mceliece460896f"))]
pub(crate) mod internals348864 {
    pub(crate) mod benes;
    pub(crate) mod bm;
    pub(crate) mod controlbits;
    pub(crate) mod decrypt;
    pub(crate) mod encrypt;
    pub(crate) mod gf_mul;
    pub(crate) mod params;
    pub(crate) mod root;
    pub(crate) mod sk_gen;
    pub(crate) mod synd;
}
