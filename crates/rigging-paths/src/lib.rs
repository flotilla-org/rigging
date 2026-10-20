//! Application directories using XDG conventions on every operating system.
use std::path::PathBuf;

use rigging_process::EnvVars;

/// Resolved directories. Resolution does not create or inspect directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPolicy {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl PathPolicy {
    /// Resolve an application's directories from an injected environment.
    ///
    /// `app` must be a single normal path component (for example `drydock`).
    /// The root override is its ASCII-uppercase name with hyphens replaced
    /// by underscores, followed by `_ROOT` (e.g. `my-app` → `MY_APP_ROOT`).
    /// Names such as `my-app` and `my_app` therefore share `MY_APP_ROOT`.
    /// A present root, including an empty value, wins over all XDG variables.
    /// Each XDG base gets the application name appended; missing bases use
    /// HOME and the XDG defaults, including on macOS. HOME is only required
    /// when a default is needed. No ambient environment fallback is used.
    pub fn from_env(app: &str, env: &dyn EnvVars) -> Result<Self, String> {
        let mut components = std::path::Path::new(app).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_))) || components.next().is_some() {
            return Err("application name must be a single normal path component".into());
        }
        if let Some(root) = env.get(&format!("{}_ROOT", app.to_ascii_uppercase().replace('-', "_"))) {
            let root = PathBuf::from(root);
            return Ok(Self {
                config_dir: root.join("config"),
                data_dir: root.join("data"),
                state_dir: root.join("state"),
                cache_dir: root.join("cache"),
            });
        }
        let resolve = |key, default| {
            let base = match env.get(key) {
                Some(value) => PathBuf::from(value),
                None => PathBuf::from(env.get("HOME").ok_or("cannot determine home directory: HOME is unset")?).join(default),
            };
            Ok::<_, String>(base.join(app))
        };
        Ok(Self {
            config_dir: resolve("XDG_CONFIG_HOME", ".config")?,
            data_dir: resolve("XDG_DATA_HOME", ".local/share")?,
            state_dir: resolve("XDG_STATE_HOME", ".local/state")?,
            cache_dir: resolve("XDG_CACHE_HOME", ".cache")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;
    use std::collections::HashMap;

    struct Env(HashMap<String, String>);
    impl EnvVars for Env {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn host_os(&self) -> &str {
            "macos"
        }
    }

    // Every category independently obeys root > XDG > HOME default, even on macOS.
    #[hegel::test]
    fn directory_precedence(tc: hegel::TestCase) {
        // Span both applications, optional root/HOME, and every subset of XDG bases.
        let app = if tc.draw(gs::booleans()) { "flotilla" } else { "drydock" };
        let root = tc.draw(gs::booleans());
        let home = tc.draw(gs::booleans());
        let mut vars = HashMap::new();
        if root {
            vars.insert(format!("{}_ROOT", app.to_ascii_uppercase().replace('-', "_")), "/root".into());
        }
        if home {
            vars.insert("HOME".into(), "/home/test".into());
        }
        let categories = [
            ("CONFIG", ".config", "config"),
            ("DATA", ".local/share", "data"),
            ("STATE", ".local/state", "state"),
            ("CACHE", ".cache", "cache"),
        ];
        let mut expected = Vec::new();
        let mut missing_home = false;
        for (category, default, directory) in categories {
            let xdg = tc.draw(gs::booleans());
            if xdg {
                vars.insert(format!("XDG_{category}_HOME"), format!("/xdg/{directory}"));
            }
            expected.push(if root {
                PathBuf::from("/root").join(directory)
            } else if xdg {
                PathBuf::from("/xdg").join(directory).join(app)
            } else {
                missing_home |= !home;
                PathBuf::from("/home/test").join(default).join(app)
            });
        }
        let result = PathPolicy::from_env(app, &Env(vars));
        if missing_home {
            assert!(result.is_err());
        } else {
            let paths = result.unwrap();
            assert_eq!(vec![paths.config_dir, paths.data_dir, paths.state_dir, paths.cache_dir], expected);
        }
    }

    // Hyphenated and underscored application names use shell-friendly overrides
    // while retaining the original application name in XDG directories.
    #[test]
    fn compound_application_names() {
        for app in ["my-app", "my_app"] {
            let env = Env(HashMap::from([("MY_APP_ROOT".into(), "/root".into())]));
            assert_eq!(PathPolicy::from_env(app, &env).unwrap().config_dir, PathBuf::from("/root/config"));
            let env = Env(HashMap::from([("HOME".into(), "/home/test".into())]));
            assert_eq!(PathPolicy::from_env(app, &env).unwrap().config_dir, PathBuf::from("/home/test/.config").join(app));
        }
    }

    // Invalid application components are refused; empty environment values retain
    // the original policy's present-value semantics rather than reading the host.
    #[test]
    fn invalid_names_and_empty_values() {
        for app in ["", ".", "..", "/absolute", "two/parts"] {
            assert!(PathPolicy::from_env(app, &Env(HashMap::new())).is_err());
        }
        let env = Env(HashMap::from([("APP_ROOT".into(), "".into())]));
        assert_eq!(PathPolicy::from_env("app", &env).unwrap().config_dir, PathBuf::from("config"));
        let env = Env(HashMap::from([("HOME".into(), "".into()), ("XDG_CONFIG_HOME".into(), "".into())]));
        let paths = PathPolicy::from_env("app", &env).unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("app"));
        assert_eq!(paths.state_dir, PathBuf::from(".local/state/app"));
    }
}
