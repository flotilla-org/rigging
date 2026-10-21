//! Locate companion binaries without searching PATH.
use crate::EnvVars;
use std::path::{Component, Path, PathBuf};

/// Resolve a nonempty override verbatim, then an existing sibling, then an existing
/// binary above `deps/` (Cargo's test executable directory).
///
/// `binary` must be one filename, including any platform suffix. Overrides
/// are not probed; empty overrides are ignored. Candidates must be files; spawn
/// checks launch permissions. The injected probes can inspect any filesystem;
/// Linux `current_exe` resolves symlinks; macOS may return the symlink path.
/// Lookup uses only the directory reported by the supplied probe.
/// local callers pass `std::env::current_exe` and `|path| path.is_file()`.
pub fn resolve_sibling_binary(
    binary: &str,
    override_var: &str,
    env: &dyn EnvVars,
    current_exe: impl FnOnce() -> std::io::Result<PathBuf>,
    is_file: impl Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    let mut components = Path::new(binary).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err("companion binary must be a single filename".into());
    }
    if let Some(path) = env.get_os(override_var).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let current = current_exe().map_err(|e| format!("can't find self: {e}"))?;
    let parent = current.parent().ok_or("current executable has no parent directory")?;
    let sibling = parent.join(binary);
    if is_file(&sibling) {
        return Ok(sibling);
    }
    if parent.file_name().is_some_and(|name| name == "deps")
        && let Some(grandparent) = parent.parent()
    {
        let candidate = grandparent.join(binary);
        if is_file(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!("failed to locate {binary} next to {}", current.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;
    struct Env(Option<String>);
    impl EnvVars for Env {
        fn get(&self, key: &str) -> Option<String> {
            assert_eq!(key, "DAEMON_BIN");
            self.0.clone()
        }
    }

    // Override > sibling > deps parent; ordinary directories never search above.
    #[hegel::test]
    fn lookup_precedence(tc: hegel::TestCase) {
        // All combinations of override, layout, absent and duplicate candidates.
        let overridden = tc.draw(gs::booleans());
        let deps = tc.draw(gs::booleans());
        let sibling = tc.draw(gs::booleans());
        let ancestor = tc.draw(gs::booleans());
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join(if deps { "deps" } else { "bin" });
        std::fs::create_dir(&parent).unwrap();
        let near = parent.join("daemon");
        let far = dir.path().join("daemon");
        if sibling {
            std::fs::write(&near, "").unwrap();
        }
        if ancestor {
            std::fs::write(&far, "").unwrap();
        }
        let env = Env(overridden.then(|| "custom-daemon".into()));
        let result = resolve_sibling_binary("daemon", "DAEMON_BIN", &env, || Ok(parent.join("cli")), |p| p.is_file());
        let expected = if overridden {
            Some(PathBuf::from("custom-daemon"))
        } else if sibling {
            Some(near)
        } else if deps && ancestor {
            Some(far)
        } else {
            None
        };
        match expected {
            Some(path) => assert_eq!(result.unwrap(), path),
            None => assert!(result.unwrap_err().contains("failed to locate daemon next to")),
        }
    }

    // A nonempty override bypasses executable and filesystem discovery.
    #[test]
    fn override_skips_probes() {
        assert_eq!(
            resolve_sibling_binary("daemon", "DAEMON_BIN", &Env(Some("custom".into())), || panic!("discovery"), |_| panic!("probe"))
                .unwrap(),
            PathBuf::from("custom")
        );
    }

    // Empty overrides fall back to discovery, and directories cannot shadow files.
    #[test]
    fn empty_override_and_directory_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let deps = dir.path().join("deps");
        std::fs::create_dir(&deps).unwrap();
        std::fs::create_dir(deps.join("daemon")).unwrap();
        let daemon = dir.path().join("daemon");
        std::fs::write(&daemon, "").unwrap();
        assert_eq!(
            resolve_sibling_binary("daemon", "DAEMON_BIN", &Env(Some("".into())), || Ok(deps.join("cli")), |p| p.is_file()).unwrap(),
            daemon
        );
    }

    // Native binary overrides must not fall through when they are not UTF-8.
    #[cfg(unix)]
    #[test]
    fn native_override_is_lossless() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        struct Native(OsString);
        impl EnvVars for Native {
            fn get(&self, _: &str) -> Option<String> {
                panic!("lossy lookup")
            }
            fn get_os(&self, _: &str) -> Option<OsString> {
                Some(self.0.clone())
            }
        }
        let value = OsString::from_vec(b"/binary/\xff".to_vec());
        assert_eq!(
            resolve_sibling_binary("daemon", "DAEMON_BIN", &Native(value.clone()), || panic!("discovery"), |_| panic!("probe")).unwrap(),
            PathBuf::from(value)
        );
    }

    // Invalid names and unavailable executable locations return contextual errors.
    #[test]
    fn invalid_and_unavailable_executable() {
        let env = Env(None);
        assert!(
            resolve_sibling_binary("daemon", "DAEMON_BIN", &env, || Err(std::io::Error::other("unavailable")), |_| panic!("probe"))
                .unwrap_err()
                .contains("can't find self: unavailable")
        );
        assert!(
            resolve_sibling_binary("daemon", "DAEMON_BIN", &env, || Ok(PathBuf::from("/")), |_| false).unwrap_err().contains("no parent")
        );
        for name in ["", ".", "..", "../daemon", "/daemon"] {
            assert!(resolve_sibling_binary(name, "DAEMON_BIN", &env, || panic!("discovery"), |_| false).is_err());
        }
    }
}
