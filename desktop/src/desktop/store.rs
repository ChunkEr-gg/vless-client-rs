use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};

use super::super::{DEFAULT_LISTEN, MAX_LINK_SIZE, parse_listen};
use vless_profile::{parse_sha256_pin, parse_vless_link};

const MAX_PROFILES: usize = 128;
const MAX_BOOK_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Book {
    pub selected: usize,
    pub listen: SocketAddr,
    pub profiles: Vec<SavedProfile>,
    pub(super) settings: super::settings::Settings,
}

impl Default for Book {
    fn default() -> Self {
        Self {
            selected: 0,
            listen: DEFAULT_LISTEN,
            settings: Default::default(),
            profiles: Vec::new(),
        }
    }
}

impl Book {
    pub fn move_selected(&mut self, target: usize) {
        self.profiles.swap(self.selected, target);
        self.selected = target;
    }

    pub fn find_link(&self, link: &str) -> Option<usize> {
        let key = link.split('#').next();
        self.profiles
            .iter()
            .position(|existing| existing.link.split('#').next() == key)
    }

    pub fn insert(&mut self, profile: SavedProfile, replace: Option<usize>) -> Result<(), String> {
        if self
            .find_link(&profile.link)
            .is_some_and(|index| Some(index) != replace)
        {
            return Err("This link is already saved.".into());
        }
        if let Some(i) = replace {
            self.profiles[i] = profile;
        } else {
            if self.profiles.len() >= MAX_PROFILES {
                return Err(format!("You can save up to {MAX_PROFILES} profiles."));
            }
            self.profiles.push(profile);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedProfile {
    pub label: String,
    pub link: String,
    pub pin: Option<String>,
    #[serde(default)]
    pub results: [String; 4],
    #[serde(skip)]
    pub details: Details,
}

#[derive(Clone, Default)]
pub struct Details {
    pub endpoint: String,
    pub sni: String,
    pub security: &'static str,
}

impl SavedProfile {
    pub fn share_link(&self) -> String {
        let mut profile = parse_vless_link(&self.link)
            .expect("validated saved link")
            .profile;
        profile.name.clone_from(&self.label);
        if let (
            Some(pin),
            vless_profile::ProfileSecurity::Ktls {
                cert_sha256_pin, ..
            },
        ) = (&self.pin, &mut profile.security)
        {
            *cert_sha256_pin = Some(parse_sha256_pin(pin).expect("validated saved pin"));
        }
        profile.to_vless_link()
    }

    pub fn new(label: &str, link: &str, pin: &str) -> Result<Self, String> {
        let link = link.trim();
        if link.len() as u64 > MAX_LINK_SIZE {
            return Err("VLESS link is too long.".into());
        }
        let pin = pin.trim();
        let pin = (!pin.is_empty()).then(|| pin.to_owned());
        let profile = parse_vless_link(link)
            .map_err(|err| err.to_string())?
            .profile;
        if let Some(pin) = &pin {
            if profile.security.is_reality() {
                return Err("REALITY uses a public key instead of a certificate pin.".into());
            }
            let explicit = parse_sha256_pin(pin).map_err(|err| err.to_string())?;
            if let vless_profile::ProfileSecurity::Ktls {
                cert_sha256_pin: Some(embedded),
                ..
            } = &profile.security
                && explicit != *embedded
            {
                return Err("Certificate pins in the link and the TLS pin field differ.".into());
            }
        }
        let host = &profile.server_host;
        let endpoint = if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]:{}", profile.server_port)
        } else {
            format!("{host}:{}", profile.server_port)
        };
        let sni = profile.security.sni().to_owned();
        let security = if profile.security.is_reality() {
            "REALITY + Vision"
        } else {
            "TLS"
        };
        let label = match label.trim() {
            "" => link
                .split_once('#')
                .map_or_else(String::new, |(_, fragment)| {
                    percent_decode_str(fragment)
                        .decode_utf8_lossy()
                        .into_owned()
                }),
            name => name.to_owned(),
        };
        let label: String = label
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();
        Ok(Self {
            label: if label.is_empty() {
                endpoint.clone()
            } else {
                label
            },
            link: link.to_owned(),
            pin,
            results: Default::default(),
            details: Details {
                endpoint,
                sni,
                security,
            },
        })
    }
}

pub struct Store {
    path: PathBuf,
    lock: File,
}

impl Store {
    pub fn open() -> Result<(Self, Book), String> {
        let dirs =
            directories::BaseDirs::new().ok_or("No user configuration directory available.")?;
        Self::open_at(dirs.config_dir().join("reality-ktls"))
    }

    fn open_at(dir: PathBuf) -> Result<(Self, Book), String> {
        let mut dirs = DirBuilder::new();
        #[cfg(unix)]
        dirs.mode(0o700);
        dirs.recursive(true)
            .create(&dir)
            .map_err(|e| format!("Could not create the profile directory: {e}"))?;
        let mut options = OpenOptions::new();
        #[cfg(unix)]
        options.mode(0o600);
        let lock = options
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("client.lock"))
            .map_err(|e| format!("Could not open the profile lock: {e}"))?;
        lock.try_lock().map_err(|e| {
            format!("Could not lock the profile store. Check for another open client window. {e}")
        })?;
        let store = Self {
            path: dir.join("client.toml"),
            lock,
        };
        let book = Self::load(&store.path).map_err(|e| format!("{}: {e}", store.path.display()))?;
        Ok((store, book))
    }

    fn load(path: &std::path::Path) -> Result<Book, String> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Book::default()),
            Err(e) => return Err(e.to_string()),
        };
        let text = io::read_to_string(file.take(MAX_BOOK_SIZE + 1)).map_err(|e| e.to_string())?;
        if text.len() as u64 > MAX_BOOK_SIZE {
            return Err("profile file is too large".into());
        }
        let book: Book = toml::from_str(&text).map_err(|_| "invalid desktop profile file")?;
        let mut checked = Book {
            selected: book.selected.min(book.profiles.len().saturating_sub(1)),
            listen: parse_listen(&book.listen.to_string())?,
            settings: book.settings,
            profiles: Vec::new(),
        };
        for (i, profile) in book.profiles.into_iter().enumerate() {
            let mut validated = SavedProfile::new(
                &profile.label,
                &profile.link,
                profile.pin.as_deref().unwrap_or_default(),
            )
            .map_err(|e| format!("profile {}: {e}", i + 1))?;
            validated.results = profile.results;
            checked.insert(validated, None)?;
        }
        Ok(checked)
    }

    pub fn save(&self, book: &Book) -> Result<(), String> {
        let encoded = toml::to_string(book).map_err(|_| "Could not encode the profile store.")?;
        if encoded.len() as u64 > MAX_BOOK_SIZE {
            return Err("The profile store is too large.".into());
        }
        let result = (|| {
            let dir = self
                .path
                .parent()
                .expect("profile file has a parent directory");
            let mut temp = tempfile::NamedTempFile::new_in(dir)?;
            temp.write_all(encoded.as_bytes())?;
            temp.as_file().sync_all()?;
            temp.persist(&self.path).map_err(|e| e.error)?;
            Ok::<_, io::Error>(())
        })();
        result.map_err(|e| format!("Could not save desktop profiles: {e}"))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // A concurrent fork can briefly retain the file descriptor before
        // exec closes it. Release the lock independently of that reference.
        let _ = self.lock.unlock();
    }
}

#[cfg(all(test, unix))]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn profiles_round_trip_privately_and_exclude_other_writers() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut book) = Store::open_at(dir.path().into()).unwrap();
        assert!(Store::open_at(dir.path().into()).is_err());
        let uri = "vless://11111111-1111-4111-8111-111111111111@[::1]:443?security=tls&sni=server.test#Test%20server";
        let pin = "ab".repeat(32);
        let profile = SavedProfile::new("", uri, &pin).unwrap();
        let mut renamed = profile.clone();
        renamed.label = "Office & home".into();
        let shared = parse_vless_link(&renamed.share_link()).unwrap().profile;
        assert_eq!(shared.name, renamed.label);
        assert!(
            matches!(shared.security, vless_profile::ProfileSecurity::Ktls {
            cert_sha256_pin: Some(bytes), ..
        } if bytes == [0xab; 32])
        );
        book.insert(profile.clone(), None).unwrap();
        assert!(book.insert(profile, None).is_err());
        assert_eq!(
            book.find_link(&uri.replace("#Test%20server", "#Renamed")),
            Some(0)
        );
        let second = SavedProfile::new("", &uri.replace(":443?", ":8443?"), &pin).unwrap();
        book.insert(second, None).unwrap();
        book.move_selected(1);
        book.listen = "[::1]:0".parse().unwrap();
        store.save(&book).unwrap();
        let path = store.path.clone();
        drop(store);
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);

        let (_, restored) = Store::open_at(dir.path().into()).unwrap();
        assert_eq!(restored.listen, book.listen);
        assert_eq!(restored.selected, 1);
        let profile = &restored.profiles[restored.selected];
        assert_eq!(restored.profiles[0].details.endpoint, "[::1]:8443");
        assert_eq!(profile.link, uri);
        assert_eq!(profile.label, "Test server");
        assert_eq!(profile.details.endpoint, "[::1]:443");
        assert_eq!(profile.details.sni, "server.test");
        assert_eq!(profile.pin.as_deref(), Some(pin.as_str()));
    }
}
