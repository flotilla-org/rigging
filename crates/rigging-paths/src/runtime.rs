//! An application's per-user runtime directory, for its sockets. Unlike
//! [`PathPolicy`](crate::PathPolicy), this looks at the filesystem: which
//! candidate exists and who owns it decides the place, so every process
//! acting for one user, however it was started, finds the same one.

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rigging_process::EnvVars;

use crate::{check_app, root_variable};

/// Where `app`'s sockets live for the user `uid`, the first of:
///
/// 1. `<APP>_ROOT/runtime`, when the root override is set; it must be absolute.
/// 2. `$XDG_RUNTIME_DIR/<app>`, when that is absolute and owned by `uid`, so a
///    `sudo -u` shell still carrying another user's variable passes it by.
/// 3. `/run/user/<uid>/<app>`, when `uid` owns that directory, which a cron
///    job or `sudo -u` shell reaches without the variable.
/// 4. `<tmp>/<app>-<uid>`, the temporary directory being `$TMPDIR` when it is
///    absolute, else `/tmp`.
pub fn runtime_dir(app: &str, uid: u32, env: &dyn EnvVars) -> Result<PathBuf, String> {
    resolve(app, uid, env, |path| fs::metadata(path).ok().filter(|metadata| metadata.is_dir()).map(|metadata| metadata.uid()))
}

/// `owner` reports who owns a directory, if it is one.
fn resolve(app: &str, uid: u32, env: &dyn EnvVars, owner: impl Fn(&Path) -> Option<u32>) -> Result<PathBuf, String> {
    check_app(app)?;
    if let Some(root) = env.get_os(&root_variable(app)) {
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            return Err("application root override must be an absolute path".into());
        }
        return Ok(root.join("runtime"));
    }
    let owned = |path: &Path| owner(path) == Some(uid);
    if let Some(base) = env.get_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|base| base.is_absolute() && owned(base)) {
        return Ok(base.join(app));
    }
    let session = PathBuf::from(format!("/run/user/{uid}"));
    if owned(&session) {
        return Ok(session.join(app));
    }
    let temporary = env.get_os("TMPDIR").map(PathBuf::from).filter(|path| path.is_absolute()).unwrap_or_else(|| "/tmp".into());
    Ok(temporary.join(format!("{app}-{uid}")))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use super::*;

    struct Env(HashMap<String, String>);
    impl EnvVars for Env {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn host_os(&self) -> &str {
            "linux"
        }
    }

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env(pairs.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect())
    }

    // Each candidate counts only when it belongs to the user; the root
    // override wins and must be absolute.
    #[test]
    fn candidates_in_order() {
        let owners = BTreeMap::from([("/run/user/1000", 1000), ("/xdg/mine", 1000), ("/xdg/theirs", 1001)]);
        let owner = |path: &Path| owners.get(path.to_str().expect("UTF-8")).copied();
        let at = |pairs: &[(&str, &str)], uid| resolve("tender", uid, &env(pairs), owner);
        assert_eq!(at(&[("TENDER_ROOT", "/root"), ("XDG_RUNTIME_DIR", "/xdg/mine")], 1000), Ok("/root/runtime".into()));
        assert!(at(&[("TENDER_ROOT", "relative")], 1000).is_err());
        assert_eq!(at(&[("XDG_RUNTIME_DIR", "/xdg/mine")], 1000), Ok("/xdg/mine/tender".into()));
        assert_eq!(at(&[("XDG_RUNTIME_DIR", "/xdg/theirs")], 1000), Ok("/run/user/1000/tender".into()), "another user's variable");
        assert_eq!(at(&[], 1000), Ok("/run/user/1000/tender".into()), "cron: no variable");
        assert_eq!(at(&[("TMPDIR", "/var/tmp")], 1001), Ok("/var/tmp/tender-1001".into()));
        assert_eq!(at(&[("TMPDIR", "relative")], 1001), Ok("/tmp/tender-1001".into()));
        assert!(resolve("../x", 1000, &env(&[]), owner).is_err());
    }
}
