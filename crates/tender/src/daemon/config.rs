use std::{
    collections::BTreeSet,
    fs::{self, File, Permissions},
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use toml::{from_str, to_string};

use crate::{Fingerprint, Scope, api::TrustedInstance};

/// `config.toml`, written by people and only read by the daemon.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "publication")]
    pub publications: Vec<ConfiguredPublication>,
    #[serde(default, rename = "grant")]
    pub grants: Vec<ConfiguredGrant>,
    /// How long a Binding outlives its publication's withdrawal, or its loss
    /// of every copy, before it is removed. Default: a minute, which covers
    /// a vessel moving host.
    pub binding_grace_seconds: Option<u64>,
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

/// A missing file is the empty default.
fn load<T: DeserializeOwned + Default>(path: &Path) -> io::Result<T> {
    match fs::read_to_string(path) {
        Ok(text) => from_str(&text).map_err(|error| io::Error::other(format!("{}: {error}", path.display()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error),
    }
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Self> {
        load(path)
    }
}

/// `trusted.toml`: the Trusted Group. It is configuration, which people may
/// edit while the daemon is stopped; the daemon rewrites it as the group
/// changes through the control API.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct TrustedFile {
    #[serde(default, rename = "instance")]
    pub instances: Vec<TrustedInstance>,
}

impl TrustedFile {
    pub fn load(path: &Path) -> io::Result<Self> {
        load(path)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let text = to_string(self).map_err(io::Error::other)?;
        let parent = path.parent().ok_or_else(|| io::Error::other("trusted group file needs a parent directory"))?;
        let mut temporary = NamedTempFile::new_in(parent)?;
        temporary.as_file().set_permissions(Permissions::from_mode(0o600))?;
        temporary.write_all(text.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        File::open(parent)?.sync_all()
    }
}
