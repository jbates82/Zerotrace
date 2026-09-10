//! Vault lifecycle: create, open, verify, import, export, close.
//!
//! # Layout
//!
//! ```text
//! [0..256)                 header (see zerotrace-format)
//! [256..manifest_offset)   authenticated chunks, back to back
//! [manifest_offset..)      manifest nonce, then the encrypted manifest
//! ```
//!
//! # Key hierarchy
//!
//! ```text
//! password --Argon2id--> KEK --unwraps--> master key
//!                                          |
//!                        +-----------------+------------------+
//!                        |                 |                  |
//!                   metadata key      per-file keys      integrity key
//!                   (HKDF, fixed)     (HKDF, salted by    (HKDF, fixed)
//!                                      random object id)
//! ```
//!
//! The password never encrypts anything directly (INV-3), and because it only
//! wraps the master key, changing it rewraps 48 bytes instead of re-encrypting
//! the vault.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use zerotrace_compress::{self as compress, CompressSuite};
use zerotrace_core::{limits, Assurance, Error, Result, VaultId};
use zerotrace_crypto::{self as crypto, CryptoSuite};
use zerotrace_format::manifest::{ChunkRef, Entry, Manifest};
use zerotrace_format::{Header, HEADER_LEN};
use zerotrace_auth::{compose_kek, AuthDescriptor, Authenticator, FactorKind, FactorSet};
use zerotrace_kdf::{derive_kek, KdfParams};
use zerotrace_split::{seal as seal_split, unseal as unseal_split, ComponentKind, SplitBundle};
use zerotrace_secure_memory::Key256;

/// Plaintext bytes per chunk. Bounds memory and localises corruption.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// zstd level used for chunk compression. Modest on purpose: the vault's job
/// is confidentiality, and a slow compressor lengthens the window in which
/// plaintext is resident.
pub const COMPRESSION_LEVEL: i32 = 3;

/// Where a vault's split bundle lives.
pub fn split_bundle_path(vault: &Path) -> PathBuf {
    PathBuf::from(format!("{}.split", vault.display()))
}

/// Settings chosen when a vault is created.
#[derive(Debug, Clone)]
pub struct VaultOptions {
    pub crypto_suite: CryptoSuite,
    pub compress_suite: CompressSuite,
    pub kdf_params: KdfParams,
    pub compression_level: i32,
    /// Which authentication factors the vault will require.
    pub factors: FactorSet,
}

impl Default for VaultOptions {
    fn default() -> Self {
        Self {
            crypto_suite: CryptoSuite::XChaCha20Poly1305,
            compress_suite: CompressSuite::Zstd,
            kdf_params: KdfParams::INTERACTIVE,
            compression_level: 3,
            factors: FactorSet::password_only(),
        }
    }
}

/// An open vault. Dropping it destroys the in-memory keys.
pub struct Vault {
    path: PathBuf,
    header: Header,
    manifest: Manifest,
    /// Present only while unlocked.
    master: Option<Key256>,
    /// First byte after the last chunk, and where the manifest begins.
    data_end: u64,
}

/// Outcome of `verify`, reported per-check rather than as one boolean.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub vault_id: VaultId,
    pub header_authentic: Assurance,
    pub manifest_authentic: Assurance,
    pub chunks_checked: usize,
    pub chunks_failed: usize,
    pub integrity_root_matches: Assurance,
    pub entries: usize,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
}

impl VerifyReport {
    pub fn is_intact(&self) -> bool {
        self.header_authentic == Assurance::Verified
            && self.manifest_authentic == Assurance::Verified
            && self.integrity_root_matches == Assurance::Verified
            && self.chunks_failed == 0
    }
}

fn manifest_aad(vault_id: &VaultId, len: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&len.to_le_bytes());
    aad
}

fn chunk_aad(object_id: &[u8; 16], index: u64, plaintext_len: u32, suite: CompressSuite) -> Vec<u8> {
    // Binding the index stops chunks being reordered, and binding the object
    // id stops a chunk being moved between files.
    let mut aad = Vec::with_capacity(30);
    aad.extend_from_slice(object_id);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&plaintext_len.to_le_bytes());
    aad.extend_from_slice(&(suite as u16).to_le_bytes());
    aad
}

/// Rejects absolute paths, drive prefixes and `..`, so a hostile manifest
/// cannot write outside the export directory.
pub fn sanitize_relative_path(p: &str) -> Result<PathBuf> {
    let raw = PathBuf::from(p.replace('\\', "/"));
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for c in raw.components() {
        match c {
            Component::Normal(s) => {
                out.push(s);
                depth += 1;
            }
            Component::CurDir => {}
            _ => return Err(Error::Format(format!("unsafe path in vault: {p}"))),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(Error::Format("entry has an empty path".into()));
    }
    if depth > limits::MAX_PATH_DEPTH {
        return Err(Error::LimitExceeded("entry path is nested too deeply".into()));
    }
    Ok(out)
}

impl Vault {
    pub fn vault_id(&self) -> VaultId {
        self.header.vault_id
    }
    pub fn crypto_suite(&self) -> CryptoSuite {
        self.header.crypto_suite
    }
    pub fn compress_suite(&self) -> CompressSuite {
        self.header.compress_suite
    }
    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf_params
    }
    /// Whether this vault requires a quorum of key components to open.
    pub fn is_split_protected(&self) -> bool {
        self.header.flags & zerotrace_format::flags::SPLIT_PROTECTED != 0
    }

    pub fn factors(&self) -> FactorSet {
        self.header.auth.required
    }
    pub fn format_version(&self) -> u16 {
        self.header.format_version
    }
    pub fn is_unlocked(&self) -> bool {
        self.master.is_some()
    }
    pub fn entries(&self) -> &[Entry] {
        &self.manifest.entries
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn master(&self) -> Result<&Key256> {
        self.master.as_ref().ok_or(Error::Locked)
    }

    /// Creates a new vault at `path`, password only.
    pub fn create<P: AsRef<Path>>(path: P, password: &[u8], opts: &VaultOptions) -> Result<Self> {
        Self::create_with(path, password, None, opts)
    }

    /// Creates a vault, optionally binding a hardware factor.
    pub fn create_with<P: AsRef<Path>>(
        path: P,
        password: &[u8],
        authenticator: Option<&dyn Authenticator>,
        opts: &VaultOptions,
    ) -> Result<Self> {
        opts.kdf_params.validate()?;
        opts.factors.validate()?;
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(Error::Other(format!("{} already exists", path.display())));
        }

        let mut kdf_salt = [0u8; zerotrace_format::SALT_LEN];
        crypto::random_bytes(&mut kdf_salt);
        let mut master_key_nonce = [0u8; 24];
        crypto::random_bytes(&mut master_key_nonce);

        let mut prf_salt = [0u8; 32];
        crypto::random_bytes(&mut prf_salt);

        let mut auth = AuthDescriptor {
            required: opts.factors,
            prf_salt,
            credential_hint: [0u8; 20],
        };

        // Obtain the hardware contribution before writing anything, so a
        // missing authenticator fails before a half-made vault exists.
        let hardware = if auth.requires_hardware() {
            let a = authenticator.ok_or(Error::NotImplemented(
                "this vault requires a FIDO2 factor but no authenticator was supplied",
            ))?;
            if a.kind() != FactorKind::Fido2Prf {
                return Err(Error::Other("authenticator is of the wrong kind".into()));
            }
            Some(a.prf_secret(&auth.credential_hint, &auth.prf_salt)?)
        } else {
            None
        };
        if !auth.requires_hardware() {
            auth.prf_salt = [0u8; 32];
        }

        let master = crypto::random_key();
        let password_key = derive_kek(password, &kdf_salt, opts.kdf_params)?;
        let kek = compose_kek(&auth, &password_key, hardware.as_ref(), &kdf_salt)?;

        let mut header = Header::new(
            opts.crypto_suite,
            opts.compress_suite,
            VaultId::from_bytes({
                let mut b = [0u8; 16];
                crypto::random_bytes(&mut b);
                b
            }),
            opts.kdf_params,
            kdf_salt,
            master_key_nonce,
            auth,
        );
        // Pin the authenticated byte image before wrapping the key.
        header.freeze();

        // Wrap the master key, binding the header's immutable prefix.
        let nonce = &master_key_nonce[..opts.crypto_suite.nonce_len()];
        let wrapped = crypto::seal(opts.crypto_suite, &kek, nonce, master.expose(), &header.aad())?;
        if wrapped.len() != zerotrace_format::WRAPPED_KEY_LEN {
            return Err(Error::Crypto("unexpected wrapped key length".into()));
        }
        header.wrapped_master_key.copy_from_slice(&wrapped);

        let mut v = Vault {
            path,
            header,
            manifest: Manifest::default(),
            master: Some(master),
            data_end: HEADER_LEN as u64,
        };
        File::create(&v.path)?;
        v.save()?;
        Ok(v)
    }

    /// Opens and unlocks a password-only vault.
    pub fn open<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        Self::open_with(path, password, None)
    }

    /// Opens a vault, supplying a hardware factor when one is required.
    ///
    /// A vault that requires FIDO2 is refused when no authenticator is given.
    /// There is no path that falls back to the password alone.
    pub fn open_with<P: AsRef<Path>>(
        path: P,
        password: &[u8],
        authenticator: Option<&dyn Authenticator>,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut f = File::open(&path)?;
        let mut hb = [0u8; HEADER_LEN];
        f.read_exact(&mut hb)
            .map_err(|_| Error::Format("file is too short to be an AZV vault".into()))?;
        let header = Header::from_bytes(&hb)?;

        // Deriving the KEK is the expensive step; the parameters driving it
        // were range-checked during parsing and are authenticated below.
        let hardware = if header.auth.requires_hardware() {
            let a = authenticator.ok_or(Error::NotImplemented(
                "this vault requires a FIDO2 factor. No authenticator was supplied, and \
                 the vault is refused rather than opened with the password alone",
            ))?;
            Some(a.prf_secret(&header.auth.credential_hint, &header.auth.prf_salt)?)
        } else {
            None
        };

        let password_key = derive_kek(password, &header.kdf_salt, header.kdf_params)?;
        let kek = compose_kek(&header.auth, &password_key, hardware.as_ref(), &header.kdf_salt)?;

        if header.flags & zerotrace_format::flags::SPLIT_PROTECTED != 0 {
            return Err(Error::Other(
                "this vault is protected by split keys and cannot be opened with a password \
                 alone. Supply the required key components; see `zt split status`"
                    .into(),
            ));
        }

        let nonce = &header.master_key_nonce[..header.crypto_suite.nonce_len()];
        let master_bytes = crypto::open(
            header.crypto_suite,
            &kek,
            nonce,
            &header.wrapped_master_key,
            &header.aad(),
        )?;
        if master_bytes.len() != 32 {
            return Err(Error::Crypto("unwrapped master key has the wrong length".into()));
        }
        let mut master = Key256::zeroed();
        master.expose_mut().copy_from_slice(&master_bytes);

        let manifest = read_manifest(&mut f, &header, &master)?;

        // The header's copy of the root is outside the authenticated prefix,
        // so the manifest's copy is authoritative and must agree.
        if manifest.integrity_root != header.integrity_root {
            return Err(Error::Integrity(
                "the header's integrity root does not match the manifest".into(),
            ));
        }
        if manifest.compute_root() != manifest.integrity_root {
            return Err(Error::Integrity("manifest integrity root is inconsistent".into()));
        }

        Ok(Vault {
            path,
            data_end: header.manifest_offset,
            header,
            manifest,
            master: Some(master),
        })
    }

    /// Opens a split-protected vault from a quorum of key components.
    ///
    /// The password still matters: it produces the user component. What
    /// changes is that the user component alone no longer unwraps anything.
    pub fn open_with_components<P: AsRef<Path>>(
        path: P,
        components: &[(ComponentKind, Key256)],
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut f = File::open(&path)?;
        let mut hb = [0u8; HEADER_LEN];
        f.read_exact(&mut hb)
            .map_err(|_| Error::Format("file is too short to be an AZV vault".into()))?;
        let header = Header::from_bytes(&hb)?;

        if header.flags & zerotrace_format::flags::SPLIT_PROTECTED == 0 {
            return Err(Error::Other(
                "this vault is not split protected; open it with a password".into(),
            ));
        }

        let bundle_path = split_bundle_path(&path);
        let bundle = SplitBundle::decode(&std::fs::read(&bundle_path).map_err(|_| {
            Error::Format(format!(
                "the split bundle {} is missing. Without it the vault cannot be opened by \
                 anyone, including its owner; restore it from a backup",
                bundle_path.display()
            ))
        })?)?;

        if bundle.vault_id != header.vault_id {
            return Err(Error::Integrity(
                "the split bundle belongs to a different vault".into(),
            ));
        }

        let release = unseal_split(&bundle, components)?;
        let nonce = &header.master_key_nonce[..header.crypto_suite.nonce_len()];
        let master_bytes = crypto::open(
            header.crypto_suite,
            &release,
            nonce,
            &header.wrapped_master_key,
            &header.aad(),
        )?;
        if master_bytes.len() != 32 {
            return Err(Error::Crypto("unwrapped master key has the wrong length".into()));
        }
        let mut master = Key256::zeroed();
        master.expose_mut().copy_from_slice(&master_bytes);

        let manifest = read_manifest(&mut f, &header, &master)?;
        if manifest.integrity_root != header.integrity_root {
            return Err(Error::Integrity(
                "the header's integrity root does not match the manifest".into(),
            ));
        }

        Ok(Vault {
            path,
            data_end: header.manifest_offset,
            header,
            manifest,
            master: Some(master),
        })
    }

    /// Converts an already-open vault to split protection.
    ///
    /// Only the 48-byte wrapped key is rewritten: the master key is unchanged,
    /// so nothing stored in the vault is re-encrypted however large it is.
    pub fn enroll_split(
        &mut self,
        components: &[(ComponentKind, Key256)],
    ) -> Result<SplitBundle> {
        if self.is_split_protected() {
            return Err(Error::Other("this vault is already split protected".into()));
        }
        let master = self.master()?.clone();

        let release = crypto::random_key();
        let bundle =
            seal_split(&release, self.header.vault_id, self.header.crypto_suite, components)?;

        // Set the flag before wrapping: it sits in the authenticated region,
        // so the wrap must commit to the vault already being split protected.
        self.header.flags |= zerotrace_format::flags::SPLIT_PROTECTED;
        let mut nonce = [0u8; 24];
        crypto::random_bytes(&mut nonce);
        self.header.master_key_nonce = nonce;
        self.header.freeze();

        let wrapped = crypto::seal(
            self.header.crypto_suite,
            &release,
            &nonce[..self.header.crypto_suite.nonce_len()],
            master.expose(),
            &self.header.aad(),
        )?;
        if wrapped.len() != zerotrace_format::WRAPPED_KEY_LEN {
            return Err(Error::Crypto("unexpected wrapped key length".into()));
        }
        self.header.wrapped_master_key.copy_from_slice(&wrapped);
        self.header.freeze();

        // Write the bundle first. If the process dies between the two writes,
        // an orphaned bundle is harmless, whereas a split-protected header
        // with no bundle would be an unopenable vault.
        std::fs::write(split_bundle_path(&self.path), bundle.encode())?;
        self.save()?;
        Ok(bundle)
    }

    /// Locks the vault, destroying the in-memory key material.
    ///
    /// This is what PANIC LOCK will call in a later phase. It leaves the vault
    /// on disk completely intact.
    pub fn close(mut self) {
        self.master = None; // Key256 zeroes itself on drop
    }

    /// Imports a file from disk under `stored_path`.
    pub fn import<P: AsRef<Path>>(&mut self, source: P, stored_path: &str) -> Result<()> {
        self.import_with_progress(source, stored_path, |_, _| {})
    }

    /// Imports a file, reporting bytes done and total as it goes.
    ///
    /// A large file takes minutes, during which a window with no feedback
    /// looks exactly like one that has hung. The callback runs once per chunk,
    /// which is often enough to move a bar and rare enough not to cost
    /// anything.
    pub fn import_with_progress<P: AsRef<Path>>(
        &mut self,
        source: P,
        stored_path: &str,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<()> {
        let master = self.master()?.clone();
        let source = source.as_ref();
        let meta = std::fs::metadata(source)?;
        if !meta.is_file() {
            return Err(Error::Other(format!("{} is not a file", source.display())));
        }
        sanitize_relative_path(stored_path)?;
        if self.manifest.entries.len() >= limits::MAX_ENTRIES {
            return Err(Error::LimitExceeded("vault holds too many entries".into()));
        }

        let mut object_id = [0u8; 16];
        crypto::random_bytes(&mut object_id);
        let file_key = crypto::derive_file_key(&master, &object_id)?;

        let expected = meta.len();
        let mut f = File::open(source)?;
        let mut out = OpenOptions::new().read(true).write(true).open(&self.path)?;
        out.seek(SeekFrom::Start(self.data_end))?;
        progress(0, expected);

        let mut chunks = Vec::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut index = 0u64;
        let mut total = 0u64;
        let mut cursor = self.data_end;

        loop {
            let n = read_full(&mut f, &mut buf)?;
            if n == 0 {
                break;
            }
            let plain = &buf[..n];
            let (used, compressed) =
                compress::compress(plain, COMPRESSION_LEVEL, self.header.compress_suite)?;
            let aad = chunk_aad(&object_id, index, n as u32, used);
            let nonce = crypto::chunk_nonce(self.header.crypto_suite, index);
            let ct = crypto::seal(self.header.crypto_suite, &file_key, &nonce, &compressed, &aad)?;
            if ct.len() > limits::MAX_CHUNK_CIPHERTEXT {
                return Err(Error::LimitExceeded("chunk ciphertext is too large".into()));
            }
            out.write_all(&ct)?;
            chunks.push(ChunkRef {
                offset: cursor,
                ciphertext_len: ct.len() as u32,
                plaintext_len: n as u32,
                hash: crypto::sha256(&ct),
            });
            cursor += ct.len() as u64;
            total += n as u64;
            index += 1;
            progress(total, expected);
            if n < CHUNK_SIZE {
                break;
            }
        }
        out.flush()?;

        // Record the suite each chunk actually used. Mixed content can end up
        // partly stored and partly compressed, so the per-chunk decision is
        // what the entry reports.
        let entry_suite = if chunks.is_empty() {
            CompressSuite::Store
        } else {
            self.header.compress_suite
        };

        self.data_end = cursor;
        self.manifest.entries.push(Entry {
            object_id,
            path: stored_path.to_string(),
            size: total,
            mtime: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            compress_suite: entry_suite,
            chunks,
        });
        self.save()
    }

    /// Exports entry `index` beneath `dest_dir`, recreating its relative path.
    pub fn export<P: AsRef<Path>>(&self, index: usize, dest_dir: P) -> Result<PathBuf> {
        self.export_with_progress(index, dest_dir, |_, _| {})
    }

    /// Exports an entry, reporting bytes done and total as it goes.
    ///
    /// Decryption is as slow as encryption on a large file, so extraction
    /// needs the same feedback importing does.
    pub fn export_with_progress<P: AsRef<Path>>(
        &self,
        index: usize,
        dest_dir: P,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<PathBuf> {
        let master = self.master()?;
        let entry = self
            .manifest
            .entries
            .get(index)
            .ok_or_else(|| Error::Other("entry index out of range".into()))?;
        let rel = sanitize_relative_path(&entry.path)?;
        let out_path = dest_dir.as_ref().join(&rel);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file_key = crypto::derive_file_key(master, &entry.object_id)?;
        let mut src = File::open(&self.path)?;
        let mut out = File::create(&out_path)?;
        let mut written = 0u64;

        progress(0, entry.size);
        for (i, c) in entry.chunks.iter().enumerate() {
            let plain = self.read_chunk(&mut src, &file_key, entry, i, c)?;
            out.write_all(&plain)?;
            written += plain.len() as u64;
            progress(written, entry.size);
        }
        out.flush()?;

        if written != entry.size {
            let _ = std::fs::remove_file(&out_path);
            return Err(Error::Integrity("exported size does not match the manifest".into()));
        }
        Ok(out_path)
    }

    fn read_chunk(
        &self,
        src: &mut File,
        file_key: &Key256,
        entry: &Entry,
        index: usize,
        c: &ChunkRef,
    ) -> Result<Vec<u8>> {
        if c.ciphertext_len as usize > limits::MAX_CHUNK_CIPHERTEXT {
            return Err(Error::LimitExceeded("chunk ciphertext exceeds the limit".into()));
        }
        src.seek(SeekFrom::Start(c.offset))?;
        let mut ct = vec![0u8; c.ciphertext_len as usize];
        src.read_exact(&mut ct)
            .map_err(|_| Error::Integrity("vault is truncated".into()))?;

        if crypto::sha256(&ct) != c.hash {
            return Err(Error::Integrity(format!(
                "chunk {index} does not match its recorded hash"
            )));
        }

        // The suite recorded on the entry is what compression *may* have been
        // used; the AAD pins which one actually was, so a swapped value fails
        // authentication rather than silently mis-decompressing.
        for suite in [entry.compress_suite, CompressSuite::Store] {
            let aad = chunk_aad(&entry.object_id, index as u64, c.plaintext_len, suite);
            let nonce = crypto::chunk_nonce(self.header.crypto_suite, index as u64);
            if let Ok(inner) =
                crypto::open(self.header.crypto_suite, file_key, &nonce, &ct, &aad)
            {
                return compress::decompress(suite, &inner, c.plaintext_len as usize);
            }
        }
        Err(Error::AuthenticationFailed)
    }

    /// Verifies the vault without exporting anything.
    pub fn verify(&self) -> Result<VerifyReport> {
        let master = self.master()?;
        let mut report = VerifyReport {
            vault_id: self.header.vault_id,
            // Both were already proven during open: the header prefix by the
            // successful unwrap, the manifest by its own AEAD.
            header_authentic: Assurance::Verified,
            manifest_authentic: Assurance::Verified,
            chunks_checked: 0,
            chunks_failed: 0,
            integrity_root_matches: Assurance::Failed,
            entries: self.manifest.entries.len(),
            plaintext_bytes: self.manifest.total_plaintext(),
            ciphertext_bytes: self.manifest.total_ciphertext(),
        };

        if self.manifest.compute_root() == self.manifest.integrity_root
            && self.manifest.integrity_root == self.header.integrity_root
        {
            report.integrity_root_matches = Assurance::Verified;
        }

        let mut src = File::open(&self.path)?;
        for entry in &self.manifest.entries {
            let file_key = crypto::derive_file_key(master, &entry.object_id)?;
            for (i, c) in entry.chunks.iter().enumerate() {
                report.chunks_checked += 1;
                if self.read_chunk(&mut src, &file_key, entry, i, c).is_err() {
                    report.chunks_failed += 1;
                }
            }
        }
        Ok(report)
    }

    /// Writes the manifest and header. Called after every mutation.
    fn save(&mut self) -> Result<()> {
        let master = self.master()?.clone();
        self.manifest.integrity_root = self.manifest.compute_root();

        let plain = self.manifest.encode();
        let metadata_key = crypto::derive_subkey(&master, b"", crypto::info::METADATA)?;
        let mut nonce_full = [0u8; 24];
        crypto::random_bytes(&mut nonce_full);
        let nonce = &nonce_full[..self.header.crypto_suite.nonce_len()];

        let aad = manifest_aad(&self.header.vault_id, plain.len() as u64);
        let ct = crypto::seal(self.header.crypto_suite, &metadata_key, nonce, &plain, &aad)?;

        let blob_len = 24 + 8 + ct.len();
        if blob_len as u64 > limits::MAX_MANIFEST_BYTES {
            return Err(Error::LimitExceeded("manifest is too large".into()));
        }

        let mut f = OpenOptions::new().read(true).write(true).open(&self.path)?;
        f.seek(SeekFrom::Start(self.data_end))?;
        f.write_all(&nonce_full)?;
        f.write_all(&(plain.len() as u64).to_le_bytes())?;
        f.write_all(&ct)?;
        let end = self.data_end + blob_len as u64;
        f.set_len(end)?;

        self.header.manifest_offset = self.data_end;
        self.header.manifest_len = blob_len as u64;
        self.header.integrity_root = self.manifest.integrity_root;

        f.seek(SeekFrom::Start(0))?;
        f.write_all(&self.header.to_bytes())?;
        f.flush()?;
        // Durability matters here: a torn write between the chunks and the
        // header would leave a vault that cannot be opened.
        f.sync_all()?;
        Ok(())
    }
}

fn read_manifest(f: &mut File, header: &Header, master: &Key256) -> Result<Manifest> {
    if header.manifest_len == 0 {
        return Ok(Manifest::default());
    }
    if header.manifest_len < 32 {
        return Err(Error::Format("manifest record is too short".into()));
    }
    f.seek(SeekFrom::Start(header.manifest_offset))?;
    let mut nonce_full = [0u8; 24];
    f.read_exact(&mut nonce_full)
        .map_err(|_| Error::Format("vault is truncated at the manifest".into()))?;
    let mut lenb = [0u8; 8];
    f.read_exact(&mut lenb)?;
    let plain_len = u64::from_le_bytes(lenb);
    if plain_len > limits::MAX_MANIFEST_BYTES {
        return Err(Error::LimitExceeded("manifest declares an implausible size".into()));
    }

    let ct_len = header.manifest_len as usize - 32;
    let mut ct = vec![0u8; ct_len];
    f.read_exact(&mut ct)
        .map_err(|_| Error::Format("vault is truncated at the manifest".into()))?;

    let metadata_key = crypto::derive_subkey(master, b"", crypto::info::METADATA)?;
    let nonce = &nonce_full[..header.crypto_suite.nonce_len()];
    let aad = manifest_aad(&header.vault_id, plain_len);
    let plain = crypto::open(header.crypto_suite, &metadata_key, nonce, &ct, &aad)?;
    Manifest::decode(&plain)
}

fn read_full(f: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}
