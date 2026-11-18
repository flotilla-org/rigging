use std::{
    collections::BTreeSet,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{Fingerprint, Scope, api::TrustedInstance};

/// `config.toml`, written by people and only read by the daemon.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "publication")]
    pub publications: Vec<ConfiguredPublication>,
    #[serde(default, rename = "grant")]
    pub grants: Vec<ConfiguredGrant>,
}

/// An endpoint published whenever the daemon runs, such as a hand-run
/// producer or a plain cleat daemon.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredPublication {
    /// Defaults to this instance's host scope, `tender/<fingerprint>`.
    pub scope: Option<String>,
    pub name: String,
    pub label: String,
    #[serde(default)]
    pub display: String,
    pub endpoint: PathBuf,
    pub audience: Option<BTreeSet<Fingerprint>>,
}

/// Another instance, such as a helper with its own key, that may publish into
/// this one under a scope, for this instance's Trusted Group.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredGrant {
    pub grantee: Fingerprint,
    pub scope: Scope,
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|error| io::Error::other(format!("{}: {error}", path.display()))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }
}

/// `trusted.toml`: the Trusted Group, which the daemon rewrites as it changes.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct TrustedFile {
    #[serde(default, rename = "instance")]
    pub instances: Vec<TrustedInstance>,
}

impl TrustedFile {
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|error| io::Error::other(format!("{}: {error}", path.display()))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let text = toml::to_string(self).map_err(io::Error::other)?;
        let parent = path.parent().ok_or_else(|| io::Error::other("trusted group file needs a parent directory"))?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
        temporary.write_all(text.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        std::fs::File::open(parent)?.sync_all()
    }
}
