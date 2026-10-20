//! Locate companion binaries without searching PATH.
use crate::EnvVars;
use std::path::{Component, Path, PathBuf};

/// Resolve an override verbatim, then an existing sibling, then an existing
/// binary above `deps/` (Cargo's test executable directory).
///
/// `binary` must be one filename, including any platform suffix. Overrides
/// (including empty values) are not probed. Existence alone is checked; spawn
/// checks launch permissions. The injected probes can inspect any filesystem;
/// local callers pass `std::env::current_exe` and `|path| path.exists()`.
pub fn resolve_sibling_binary(
    binary: &str,
    override_var: &str,
    env: &dyn EnvVars,
    current_exe: impl FnOnce() -> std::io::Result<PathBuf>,
    exists: impl Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    let mut components = Path::new(binary).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err("companion binary must be a single filename".into());
    }
    if let Some(path) = env.get(override_var) {
        return Ok(PathBuf::from(path));
    }
    let current = current_exe().map_err(|e| format!("can't find self: {e}"))?;
    let parent = current.parent().ok_or("current executable has no parent directory")?;
    let sibling = parent.join(binary);
    if exists(&sibling) {
        return Ok(sibling);
    }
    if parent.file_name().is_some_and(|name| name == "deps")
        && let Some(grandparent) = parent.parent()
    {
        let candidate = grandparent.join(binary);
        if exists(&candidate) {
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
        let result = resolve_sibling_binary("daemon", "DAEMON_BIN", &env, || Ok(parent.join("cli")), |p| p.exists());
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

    // Even an empty override bypasses executable and filesystem discovery.
    #[test]
    fn override_skips_probes() {
        assert_eq!(
            resolve_sibling_binary("daemon", "DAEMON_BIN", &Env(Some("".into())), || panic!("discovery"), |_| panic!("probe")).unwrap(),
            PathBuf::new()
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
