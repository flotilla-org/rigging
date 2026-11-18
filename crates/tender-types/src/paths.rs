//! Where an account's Tender sockets live, so a client finds its daemon and
//! computes a Binding's Local Endpoint without asking for it.

use std::{
    ffi::OsString,
    fmt::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::PublicationId;

/// The longest Unix socket path this rule produces, in bytes: `sun_path` holds
/// 104 bytes with its terminating NUL on macOS, and 108 on Linux.
pub const MAX_SOCKET_PATH: usize = 103;

/// `$TENDER_ROOT/runtime`, else `$XDG_RUNTIME_DIR/tender`, else `tender-<uid>`
/// in the temporary directory. `env` reads one environment variable.
pub fn runtime_dir(env: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, String> {
    let set = |key: &str| env(key).filter(|value| !value.is_empty()).map(PathBuf::from);
    if let Some(root) = set("TENDER_ROOT") {
        // A relative root would put sockets wherever the process started.
        return if root.is_absolute() { Ok(root.join("runtime")) } else { Err("TENDER_ROOT must be an absolute path".into()) };
    }
    if let Some(base) = set("XDG_RUNTIME_DIR").filter(|base| base.is_absolute()) {
        return Ok(base.join("tender"));
    }
    Ok(std::env::temp_dir().join(fallback_name()))
}

/// [`runtime_dir`] from this process's environment.
pub fn runtime_dir_from_env() -> Result<PathBuf, String> {
    runtime_dir(|key| std::env::var_os(key))
}

#[cfg(unix)]
fn fallback_name() -> String {
    // SAFETY: geteuid has no preconditions.
    format!("tender-{}", unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
fn fallback_name() -> String {
    "tender".into()
}

/// The control API's Local Endpoint.
pub fn control_socket(runtime: &Path) -> PathBuf {
    runtime.join("control")
}

/// Where other instances reach this one's Tender protocol.
pub fn peer_socket(runtime: &Path) -> PathBuf {
    runtime.join("peer")
}

pub fn bindings_dir(runtime: &Path) -> PathBuf {
    runtime.join("b")
}

/// A Binding's Local Endpoint: one file in [`bindings_dir`], named
/// `<scope>,<name>` with every byte outside `[A-Za-z0-9._-]` written as `%XX`,
/// so distinct identities never share a name. When that path would exceed
/// [`MAX_SOCKET_PATH`], the name is `~` and the first 32 hex digits of the
/// SHA-256 of the scope's length (8 bytes, big-endian), the scope and the name.
/// A runtime directory longer than 66 bytes cannot hold every Binding.
pub fn binding_path(runtime: &Path, id: &PublicationId) -> PathBuf {
    let directory = bindings_dir(runtime);
    let mut readable = String::new();
    encode(&id.scope.0, &mut readable);
    readable.push(',');
    encode(&id.name, &mut readable);
    let path = directory.join(readable);
    if path.as_os_str().len() <= MAX_SOCKET_PATH {
        return path;
    }
    let mut hash = Sha256::new();
    hash.update((id.scope.0.len() as u64).to_be_bytes());
    hash.update(id.scope.0.as_bytes());
    hash.update(id.name.as_bytes());
    let digest = hash.finalize();
    let mut hashed = String::from("~");
    for byte in &digest[..16] {
        let _ = write!(hashed, "{byte:02x}");
    }
    directory.join(hashed)
}

fn encode(text: &str, out: &mut String) {
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
}

#[cfg(test)]
mod tests {
    use hegel::generators as gs;

    use super::*;

    fn decode(component: &str) -> Option<(String, String)> {
        fn unescape(text: &str) -> Option<String> {
            let bytes = text.as_bytes();
            let mut out = Vec::new();
            let mut index = 0;
            while index < bytes.len() {
                if bytes[index] == b'%' {
                    out.push(u8::from_str_radix(text.get(index + 1..index + 3)?, 16).ok()?);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            String::from_utf8(out).ok()
        }
        let (scope, name) = component.split_once(',')?;
        Some((unescape(scope)?, unescape(name)?))
    }

    // Any scope and name, under any runtime directory short enough to hold
    // Bindings: one component below the Bindings directory, within the socket
    // limit, readable when it fits and then decoding back to the identity.
    #[hegel::test]
    fn binding_paths_are_single_bounded_components(tc: hegel::TestCase) {
        let scope = tc.draw(gs::text().max_size(80));
        let name = tc.draw(gs::text().max_size(80));
        let depth = tc.draw(gs::integers::<usize>().min_value(1).max_value(65));
        let runtime = PathBuf::from(format!("/{}", "r".repeat(depth)));
        let id = PublicationId::new(scope.clone(), name.clone());
        let path = binding_path(&runtime, &id);
        assert_eq!(path.parent(), Some(bindings_dir(&runtime).as_path()));
        assert!(path.as_os_str().len() <= MAX_SOCKET_PATH, "{path:?}");
        assert_eq!(binding_path(&runtime, &id), path);
        let component = path.file_name().and_then(|name| name.to_str()).expect("UTF-8 component");
        assert!(component != "." && component != ".." && !component.contains('/'));
        match component.strip_prefix('~') {
            Some(hashed) => assert_eq!(hashed.len(), 32),
            None => assert_eq!(decode(component), Some((scope, name))),
        }
    }

    // A short identity reads as itself; one past the limit is hashed.
    #[test]
    fn readable_until_the_limit() {
        let runtime = Path::new("/run/user/1000/tender");
        let path = binding_path(runtime, &PublicationId::new("vessel/abc", "cleat/default"));
        assert_eq!(path, Path::new("/run/user/1000/tender/b/vessel%2Fabc,cleat%2Fdefault"));
        let long = binding_path(runtime, &PublicationId::new("vessel/abc", "x".repeat(80)));
        assert!(long.file_name().unwrap().to_str().unwrap().starts_with('~'));
        assert_ne!(long, binding_path(runtime, &PublicationId::new("vessel/abc", "x".repeat(81))));
    }

    #[test]
    fn runtime_directory_precedence() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| OsString::from(v))
        };
        assert_eq!(runtime_dir(env(&[("TENDER_ROOT", "/root"), ("XDG_RUNTIME_DIR", "/run/user/1")])).unwrap(), Path::new("/root/runtime"));
        assert!(runtime_dir(env(&[("TENDER_ROOT", "relative")])).is_err());
        assert_eq!(runtime_dir(env(&[("XDG_RUNTIME_DIR", "/run/user/1")])).unwrap(), Path::new("/run/user/1/tender"));
        assert!(runtime_dir(env(&[("XDG_RUNTIME_DIR", "relative")])).unwrap().starts_with(std::env::temp_dir()));
    }
}
