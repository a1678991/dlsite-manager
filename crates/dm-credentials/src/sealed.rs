//! Credential vault encrypted with a key kept in the OS credential store.
//!
//! Only a random 32-byte vault key lives in the OS store (macOS Keychain,
//! Windows Credential Manager, or a Secret Service provider such as GNOME
//! Keyring or KWallet on Linux). The credentials themselves stay in a local
//! file sealed with XChaCha20-Poly1305. Stored sessions are several KiB, which
//! exceeds the Windows Credential Manager blob limit (2560 bytes), and a single
//! OS entry also means a single access prompt where the OS asks for one.

use crate::{
    set_private_file_permissions, write_private_file, CredentialRef, CredentialStore,
    CredentialsError, PasswordFile, Result,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MAGIC: &[u8; 8] = b"DMVAULT1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const VAULT_KEY_USER: &str = "credential-vault-key";

/// Where the vault key is kept.
pub trait VaultKeySource: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>>;
    fn save(&self, key: &[u8]) -> Result<()>;
}

/// Vault key stored in the platform credential store chosen by `keyring`.
#[derive(Debug, Clone)]
pub struct OsVaultKeySource {
    service: String,
}

impl OsVaultKeySource {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry> {
        Ok(keyring::Entry::new(&self.service, VAULT_KEY_USER)?)
    }
}

impl VaultKeySource for OsVaultKeySource {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        match self.entry()?.get_secret() {
            Ok(key) => Ok(Some(key)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, key: &[u8]) -> Result<()> {
        Ok(self.entry()?.set_secret(key)?)
    }
}

/// Credential store whose file is encrypted with a key from a [`VaultKeySource`].
///
/// The key is fetched on first use, so an OS unlock prompt appears only when
/// credentials are needed. A plaintext vault at `legacy_path` is imported into
/// the sealed file and removed once the key is available.
pub struct SealedCredentialStore {
    path: PathBuf,
    legacy_path: PathBuf,
    key_source: Arc<dyn VaultKeySource>,
    cipher: Mutex<Option<XChaCha20Poly1305>>,
}

impl SealedCredentialStore {
    pub fn new(
        path: impl Into<PathBuf>,
        legacy_path: impl Into<PathBuf>,
        key_source: Arc<dyn VaultKeySource>,
    ) -> Self {
        Self {
            path: path.into(),
            legacy_path: legacy_path.into(),
            key_source,
            cipher: Mutex::new(None),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Fetches (or creates) the vault key, imports any legacy vault and makes
    /// sure the sealed file exists, so later starts never fall back to plaintext.
    pub fn initialize(&self) -> Result<()> {
        self.with_vault(|vault| {
            if vault.path.exists() {
                return Ok(());
            }
            vault.save(&PasswordFile::default())
        })
    }

    fn with_vault<T>(&self, operation: impl FnOnce(&mut Vault<'_>) -> Result<T>) -> Result<T> {
        let mut cipher = self
            .cipher
            .lock()
            .map_err(|_| CredentialsError::StorePoisoned)?;

        if cipher.is_none() {
            *cipher = Some(self.open_cipher()?);
        }

        let mut vault = Vault {
            path: &self.path,
            cipher: cipher.as_ref().expect("cipher was just set"),
        };
        operation(&mut vault)
    }

    fn open_cipher(&self) -> Result<XChaCha20Poly1305> {
        let key = match self.key_source.load()? {
            Some(key) => key,
            None => {
                // A sealed file without its key cannot be read; keep it aside
                // in case the key comes back, and start an empty vault.
                set_aside_unreadable(&self.path)?;
                let mut key = vec![0u8; KEY_LEN];
                getrandom::fill(&mut key).map_err(|_| CredentialsError::Random)?;
                self.key_source.save(&key)?;
                key
            }
        };
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| CredentialsError::InvalidVaultKey)?;

        self.import_legacy(&cipher)?;
        Ok(cipher)
    }

    fn import_legacy(&self, cipher: &XChaCha20Poly1305) -> Result<()> {
        let legacy = match fs::read_to_string(&self.legacy_path) {
            Ok(content) if content.trim().is_empty() => PasswordFile::default(),
            Ok(content) => serde_json::from_str(&content)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let vault = Vault {
            path: &self.path,
            cipher,
        };
        let mut file = vault.load()?;

        for (credential_ref, password) in legacy.passwords {
            file.passwords.entry(credential_ref).or_insert(password);
        }
        vault.save(&file)?;
        fs::remove_file(&self.legacy_path)?;
        Ok(())
    }
}

impl CredentialStore for SealedCredentialStore {
    fn save_password(&self, credential_ref: &CredentialRef, password: &str) -> Result<()> {
        self.with_vault(|vault| {
            let mut file = vault.load()?;
            file.passwords
                .insert(credential_ref.as_str().to_owned(), password.to_owned());
            vault.save(&file)
        })
    }

    fn load_password(&self, credential_ref: &CredentialRef) -> Result<Option<String>> {
        self.with_vault(|vault| Ok(vault.load()?.passwords.remove(credential_ref.as_str())))
    }

    fn delete_password(&self, credential_ref: &CredentialRef) -> Result<()> {
        self.with_vault(|vault| {
            let mut file = vault.load()?;
            if file.passwords.remove(credential_ref.as_str()).is_some() {
                vault.save(&file)?;
            }
            Ok(())
        })
    }
}

struct Vault<'a> {
    path: &'a Path,
    cipher: &'a XChaCha20Poly1305,
}

impl Vault<'_> {
    fn load(&self) -> Result<PasswordFile> {
        let sealed = match fs::read(self.path) {
            Ok(sealed) => sealed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(PasswordFile::default())
            }
            Err(error) => return Err(error.into()),
        };

        match open(self.cipher, &sealed) {
            Some(plaintext) => Ok(serde_json::from_slice(&plaintext)?),
            None => {
                // Wrong key (the OS entry was replaced) or a damaged file.
                set_aside_unreadable(self.path)?;
                Ok(PasswordFile::default())
            }
        }
    }

    fn save(&self, file: &PasswordFile) -> Result<()> {
        let plaintext = serde_json::to_vec(file)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| CredentialsError::Random)?;
        let ciphertext = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: MAGIC,
                },
            )
            .map_err(|_| CredentialsError::Seal)?;

        let mut sealed = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);

        let temporary_path = self.path.with_extension("sealed.tmp");
        write_private_file(&temporary_path, &sealed)?;
        fs::rename(&temporary_path, self.path)?;
        set_private_file_permissions(self.path)
    }
}

fn open(cipher: &XChaCha20Poly1305, sealed: &[u8]) -> Option<Vec<u8>> {
    let body = sealed.strip_prefix(MAGIC.as_slice())?;
    if body.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = body.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;

    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC,
            },
        )
        .ok()
}

fn set_aside_unreadable(path: &Path) -> Result<()> {
    match fs::rename(path, path.with_extension("sealed.unreadable")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{open_credential_store_with, CredentialBackend, LocalCredentialStore};

    #[derive(Default)]
    pub(crate) struct MemoryKeySource {
        key: Mutex<Option<Vec<u8>>>,
    }

    impl VaultKeySource for MemoryKeySource {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            Ok(self.key.lock().unwrap().clone())
        }

        fn save(&self, key: &[u8]) -> Result<()> {
            *self.key.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }
    }

    struct UnavailableKeySource;

    impl VaultKeySource for UnavailableKeySource {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            Err(keyring::Error::NoStorageAccess("no secret service".into()).into())
        }

        fn save(&self, _key: &[u8]) -> Result<()> {
            Err(keyring::Error::NoStorageAccess("no secret service".into()).into())
        }
    }

    fn password_ref() -> CredentialRef {
        CredentialRef::account_password("account-a").unwrap()
    }

    #[test]
    fn sealed_store_round_trips_without_plaintext_on_disk() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let keys = Arc::new(MemoryKeySource::default());
        let store = SealedCredentialStore::new(
            dir.path().join("vault.sealed"),
            dir.path().join("vault.json"),
            keys.clone(),
        );

        store.save_password(&password_ref(), "secret-value")?;
        let on_disk = fs::read(store.path())?;
        assert!(on_disk.starts_with(MAGIC));
        assert!(!on_disk
            .windows(b"secret-value".len())
            .any(|w| w == b"secret-value"));

        let reopened =
            SealedCredentialStore::new(store.path(), dir.path().join("vault.json"), keys);
        assert_eq!(
            reopened.load_password(&password_ref())?,
            Some("secret-value".to_owned())
        );
        reopened.delete_password(&password_ref())?;
        assert_eq!(reopened.load_password(&password_ref())?, None);
        Ok(())
    }

    #[test]
    fn sessions_larger_than_the_windows_blob_limit_fit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let keys = Arc::new(MemoryKeySource::default());
        let store = SealedCredentialStore::new(
            dir.path().join("vault.sealed"),
            dir.path().join("vault.json"),
            keys.clone(),
        );
        let session_ref = CredentialRef::account_session("account-a")?;
        let session = "c".repeat(16 * 1024);

        store.save_password(&session_ref, &session)?;
        assert_eq!(store.load_password(&session_ref)?, Some(session));
        assert_eq!(keys.load()?.map(|key| key.len()), Some(KEY_LEN));
        Ok(())
    }

    #[test]
    fn legacy_plaintext_vault_is_imported_and_removed() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let legacy_path = dir.path().join("vault.json");
        LocalCredentialStore::open(&legacy_path)?.save_password(&password_ref(), "legacy")?;

        let opened = open_credential_store_with(dir.path(), Arc::new(MemoryKeySource::default()))?;

        assert_eq!(opened.backend, CredentialBackend::OsCredentialStore);
        assert!(!legacy_path.exists());
        assert_eq!(
            opened.store.load_password(&password_ref())?,
            Some("legacy".to_owned())
        );
        Ok(())
    }

    #[test]
    fn falls_back_to_plaintext_only_before_a_sealed_vault_exists() -> Result<()> {
        let dir = tempfile::tempdir()?;

        let opened = open_credential_store_with(dir.path(), Arc::new(UnavailableKeySource))?;
        assert!(matches!(
            opened.backend,
            CredentialBackend::LocalFile { .. }
        ));
        opened.store.save_password(&password_ref(), "plain")?;

        // A run with a working OS store seals the vault...
        let keys = Arc::new(MemoryKeySource::default());
        let opened = open_credential_store_with(dir.path(), keys)?;
        assert_eq!(opened.backend, CredentialBackend::OsCredentialStore);

        // ...after which an unavailable OS store is an error, not a downgrade.
        let opened = open_credential_store_with(dir.path(), Arc::new(UnavailableKeySource))?;
        assert_eq!(opened.backend, CredentialBackend::OsCredentialStore);
        assert!(matches!(
            opened.store.load_password(&password_ref()),
            Err(CredentialsError::Os(_))
        ));
        assert!(!dir.path().join("vault.json").exists());
        Ok(())
    }

    #[test]
    fn unreadable_vault_is_set_aside_when_the_key_changes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("vault.sealed");
        let legacy = dir.path().join("vault.json");
        SealedCredentialStore::new(&path, &legacy, Arc::new(MemoryKeySource::default()))
            .save_password(&password_ref(), "old")?;

        let other_key = Arc::new(MemoryKeySource::default());
        other_key.save(&[7u8; KEY_LEN])?;
        let store = SealedCredentialStore::new(&path, &legacy, other_key);

        assert_eq!(store.load_password(&password_ref())?, None);
        assert!(path.with_extension("sealed.unreadable").exists());
        Ok(())
    }

    /// Uses the real OS credential store; run with `cargo test -- --ignored`
    /// in a desktop session (Keychain, Credential Manager or Secret Service).
    #[test]
    #[ignore = "touches the OS credential store"]
    fn os_credential_store_round_trip() -> Result<()> {
        let service = format!("dev.ashrimp.dlsite-manager.test.{}", std::process::id());
        let source = OsVaultKeySource::new(&service);
        let dir = tempfile::tempdir()?;

        let opened = open_credential_store_with(dir.path(), Arc::new(source.clone()))?;
        assert_eq!(opened.backend, CredentialBackend::OsCredentialStore);
        opened.store.save_password(&password_ref(), "os-secret")?;

        let reopened = open_credential_store_with(dir.path(), Arc::new(source.clone()))?;
        assert_eq!(
            reopened.store.load_password(&password_ref())?,
            Some("os-secret".to_owned())
        );

        source.entry()?.delete_credential()?;
        Ok(())
    }
}
