# Changelog
All changes to the software that can be noticed from the users' perspective should have an entry in
this file. Except very minor things that will not affect functionality.

### Format

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

Entries should have the imperative form, just like commit messages. Start each entry with words like
add, fix, increase, force etc.. Not added, fixed, increased, forced etc.

Line wrap the file at 100 chars.                                              That is over here -> |

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.


## [3.1.0] - 2025-02-02
### Changed
- Reduce stack usage on alloc
- (refactor lib) Test kem interface against KATs
- Prefer div_ceil() over manual implementation
### Added
- Enable assertions outside test functionality only in debug mode
### Fixed
- Update dependencies to latest versions
- Fix clippy warnings eliding explicit lifetimes
- Fix clippy warning needless_doctest_main by allowing it globally
- Cleanup: remove orphaned feature guards

## [3.0.0] - 2022-01-26
### Changed
- Change from implementing NIST round 3 specification of Classic McEliece to
  [NIST round 4](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-4-submissions)
- Move non kem-API interface related tests out of kem module
- Exclude testdata folder & files from published crates in order reduce crate size
### Added
- Add a separate CHANGELOG.md file to the project
- Added tests for the Ciphertext EncappedKeySize, such that
  `CryptoCiphertextBytesTypenum` always matches the length of `CRYPTO_CIPHERTEXTBYTES`
### Fixed
- Improve & fix unit tests
- fix casting to same type clippy warnings

## [2.0.2] - 2023-01-29
### Changed
- Exclude testdata folder & files from published crates in order reduce crate size

## [2.0.1] - 2022-09-08
### Fixed
- Fix README documentation

## [2.0.0] - 2022-09-06
### Added
- Implement zeroize functionality on structs holding sensitive key material
- Implement RustCrypto's `kem` API
- Add `alloc` feature that exposes convenient helper functions to automatically
  allocate large key material on the heap

### Changed
- Rewrite a lot of the public API


## [1.1.0] - 2022-09-06
### Changed
- Make SHAKE implementation infallible
- Forbid unsafe code


## [1.0.1] - 2022-04-12
### Fixed
- Fix Copy and paste mistakes in documentation


## [1.0.0] - 2022-04-01
- public release (no April fools though). Implements
  [NIST round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions)
  version of Classic McEliece.
