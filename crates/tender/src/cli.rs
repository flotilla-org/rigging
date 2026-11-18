//! The `tender` command: the daemon, and a client of its control API for
//! people and scripts.

use std::{collections::BTreeSet, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use reqwest::{Method, Request, Url, header};
use rigging_http_client::{HttpClient, ReqwestHttpClient, http_channel_label};
use rigging_ssh::{DEFAULT_CONNECT_TIMEOUT, OpenSsh, SshSession, Target};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    Fingerprint, Label, PublicKey, PublicationId,
    api::{
        self, BindingEntry, Diagnostics, ErrorBody, Instance, PeerRoute, PublicationList, PublishEndpoint, TrustedInstance, TrustedMember,
        Untrust,
    },
    paths,
};

#[derive(Parser)]
#[command(name = "tender", about = "Publish this account's local endpoints and keep Bindings to the Trusted Group's publications")]
struct Cli {
    /// Print JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run this account's daemon until SIGINT or SIGTERM.
    Serve,
    /// This instance's key, fingerprint and peer socket.
    Identity,
    /// Publish an existing Unix socket. Tender never starts it.
    Publish(Publish),
    /// Withdraw a publication this instance made.
    Withdraw(Identity),
    /// The publications this instance hosts.
    Publications,
    /// This machine's Bindings, with their state and Local Endpoint.
    Bindings,
    /// The Local Endpoint of an identity's Binding, computed without the daemon.
    Path(Identity),
    /// Manage the Trusted Group.
    #[command(subcommand)]
    Trust(Trust),
    Diagnostics,
}

#[derive(Args)]
struct Identity {
    scope: String,
    name: String,
}

#[derive(Args)]
struct Publish {
    scope: String,
    name: String,
    #[arg(long)]
    endpoint: PathBuf,
    /// The protocol the endpoint speaks, such as `cleat` or `http`.
    #[arg(long)]
    label: String,
    #[arg(long, default_value = "")]
    display: String,
    /// A fingerprint that may bind it; repeat for more. Default: the Trusted Group.
    #[arg(long = "audience")]
    audience: Vec<String>,
}

#[derive(Subcommand)]
enum Trust {
    List,
    /// Trust an instance's public key, and follow it if a route is given.
    Add {
        key: String,
        #[arg(long, default_value = "")]
        name: String,
        /// The member's peer socket, on this machine or, with --ssh, on its own.
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long, requires = "socket")]
        ssh: Option<String>,
    },
    Remove {
        fingerprint: String,
    },
    /// Exchange keys with the instance at an SSH destination, so each trusts
    /// the other and this one follows it over SSH. This trusts whatever key
    /// the instance there presents: the SSH destination's own authentication
    /// is all that vouches for it.
    Pair {
        destination: String,
        /// What this instance calls the other one. Default: the destination.
        #[arg(long)]
        name: Option<String>,
        /// What the other one calls this instance. Default: this host's name.
        #[arg(long)]
        as_name: Option<String>,
        /// How to run `tender` on the far side.
        #[arg(long, default_value = "tender")]
        remote_tender: String,
    },
    /// The far side of `pair`: trust the key and print this instance as JSON.
    Accept {
        key: String,
        #[arg(long, default_value = "")]
        name: String,
    },
}

pub async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let runtime = paths::runtime_dir_from_env()?;
    let control = Control::new(&paths::control_socket(&runtime))?;
    let json = cli.json;
    match cli.command {
        Command::Serve => {
            let paths = crate::daemon::Paths::from_env(&rigging_process::ProcessEnvVars)?;
            crate::daemon::serve(paths).await.map_err(|error| error.to_string())
        }
        Command::Identity => {
            let instance: Instance = control.get(api::IDENTITY).await?;
            show(json, &instance, || {
                format!("{}\nfingerprint {}\npeer socket {}", instance.key.0, instance.fingerprint.0, instance.peer_socket.display())
            })
        }
        Command::Publish(publish) => {
            let audience = (!publish.audience.is_empty()).then(|| publish.audience.into_iter().map(Fingerprint).collect::<BTreeSet<_>>());
            let request = PublishEndpoint {
                id: PublicationId::new(publish.scope, publish.name),
                label: Label(publish.label),
                display: publish.display,
                endpoint: publish.endpoint,
                audience,
            };
            let publication: crate::Publication = control.post(api::PUBLISH, &request).await?;
            show(json, &publication, || format!("{} {:?} generation {}", publication.id, publication.availability, publication.generation))
        }
        Command::Withdraw(identity) => {
            let () = control.post(api::WITHDRAW, &PublicationId::new(identity.scope, identity.name)).await?;
            Ok(())
        }
        Command::Publications => {
            let list: PublicationList = control.get(api::PUBLICATIONS).await?;
            show(json, &list, || {
                list.publications
                    .iter()
                    .map(|entry| {
                        let publication = &entry.publication;
                        format!("{}\t{}\t{:?}\t{}", publication.id, publication.label.0, publication.availability, publication.display)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }
        Command::Bindings => {
            let entries: Vec<BindingEntry> = control.get(api::BINDINGS).await?;
            show(json, &entries, || {
                entries
                    .iter()
                    .map(|entry| {
                        format!("{}\t{}\t{}\t{}", entry.publication, entry.label.0, describe(&entry.state), entry.local_endpoint.display())
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }
        Command::Path(identity) => {
            let path = paths::binding_path(&runtime, &PublicationId::new(identity.scope, identity.name));
            show(json, &path, || path.display().to_string())
        }
        Command::Trust(trust) => self::trust(&control, json, trust).await,
        Command::Diagnostics => {
            let diagnostics: Diagnostics = control.get(api::DIAGNOSTICS).await?;
            show(json, &diagnostics, || {
                let mut lines = vec![
                    format!("instance {}", diagnostics.instance.fingerprint.0),
                    format!(
                        "publications {}, bindings {}, trusted {}",
                        diagnostics.publications, diagnostics.bindings, diagnostics.trusted
                    ),
                ];
                lines.extend(diagnostics.peers.iter().map(|peer| format!("peer {} {}: {:?}", peer.fingerprint.0, peer.name, peer.state)));
                lines.join("\n")
            })
        }
    }
}

async fn trust(control: &Control, json: bool, trust: Trust) -> Result<(), String> {
    match trust {
        Trust::List => {
            let members: Vec<TrustedMember> = control.get(api::TRUSTED).await?;
            show(json, &members, || {
                members
                    .iter()
                    .map(|member| format!("{}\t{}\t{}", member.fingerprint.0, member.instance.name, route(&member.instance.route)))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }
        Trust::Add { key, name, socket, ssh } => {
            let instance = TrustedInstance { key: PublicKey(key), name, route: socket.map(|socket| PeerRoute { ssh, socket }) };
            let member: TrustedMember = control.post(api::TRUSTED, &instance).await?;
            show(json, &member, || member.fingerprint.0.clone())
        }
        Trust::Remove { fingerprint } => {
            let () = control.post(api::UNTRUST, &Untrust { fingerprint: Fingerprint(fingerprint) }).await?;
            Ok(())
        }
        Trust::Accept { key, name } => {
            let key = PublicKey(key);
            // A member this side already reaches keeps its route; only a new
            // member is trusted without one.
            let members: Vec<TrustedMember> = control.get(api::TRUSTED).await?;
            let route = members.into_iter().find(|member| member.instance.key == key).and_then(|member| member.instance.route);
            let _: TrustedMember = control.post(api::TRUSTED, &TrustedInstance { key, name, route }).await?;
            let instance: Instance = control.get(api::IDENTITY).await?;
            println!("{}", serde_json::to_string(&instance).map_err(|error| error.to_string())?);
            Ok(())
        }
        Trust::Pair { destination, name, as_name, remote_tender } => {
            let own: Instance = control.get(api::IDENTITY).await?;
            let as_name = as_name.unwrap_or_else(hostname);
            // SSH carries the exchange; each side's trust is the other's key.
            let session = OpenSsh::connect(Target::Ambient { destination: destination.clone() }, DEFAULT_CONNECT_TIMEOUT)
                .await
                .map_err(|error| format!("ssh {destination}: {error}"))?;
            let command = format!("{remote_tender} trust accept {} --name {}", quote(&own.key.0), quote(&as_name));
            let output = session.exec(&command).await.map_err(|error| format!("ssh {destination}: {error}"))?;
            if !output.status.success() {
                return Err(format!("{destination}: {}", String::from_utf8_lossy(&output.stderr).trim()));
            }
            let remote: Instance = serde_json::from_slice(&output.stdout)
                .map_err(|error| format!("{destination} answered something other than an instance: {error}"))?;
            let instance = TrustedInstance {
                key: remote.key,
                name: name.unwrap_or_else(|| destination.clone()),
                route: Some(PeerRoute { ssh: Some(destination), socket: remote.peer_socket }),
            };
            let member: TrustedMember = control.post(api::TRUSTED, &instance).await?;
            show(json, &member, || format!("paired with {} ({})", member.instance.name, member.fingerprint.0))
        }
    }
}

fn show<T: Serialize>(json: bool, value: &T, text: impl FnOnce() -> String) -> Result<(), String> {
    if json {
        println!("{}", serde_json::to_string_pretty(value).map_err(|error| error.to_string())?);
    } else {
        let text = text();
        if !text.is_empty() {
            println!("{text}");
        }
    }
    Ok(())
}

fn describe(state: &crate::BindingState) -> String {
    match state {
        crate::BindingState::Available { route } => format!("available via {}", route.instance.0),
        crate::BindingState::Unavailable { reason, .. } => format!("unavailable ({reason:?})"),
        crate::BindingState::Revoked => "revoked".into(),
    }
}

fn route(route: &Option<PeerRoute>) -> String {
    match route {
        None => "not followed".into(),
        Some(PeerRoute { ssh: Some(destination), socket }) => format!("ssh {destination} {}", socket.display()),
        Some(PeerRoute { ssh: None, socket }) => socket.display().to_string(),
    }
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn hostname() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is writable for its whole length.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return String::new();
    }
    let end = buffer.iter().position(|&byte| byte == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

struct Control(ReqwestHttpClient);

impl Control {
    fn new(socket: &std::path::Path) -> Result<Self, String> {
        Ok(Self(ReqwestHttpClient::local(socket)?))
    }

    async fn get<R: DeserializeOwned>(&self, path: &str) -> Result<R, String> {
        self.call::<(), R>(Method::GET, path, None).await
    }

    async fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R, String> {
        self.call(Method::POST, path, Some(body)).await
    }

    async fn call<T: Serialize, R: DeserializeOwned>(&self, method: Method, path: &str, body: Option<&T>) -> Result<R, String> {
        let url = Url::parse(&format!("http://tender{path}")).map_err(|error| error.to_string())?;
        let mut request = Request::new(method.clone(), url);
        request.headers_mut().insert(header::ACCEPT, header::HeaderValue::from_static("application/json"));
        if let Some(body) = body {
            request.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
            *request.body_mut() = Some(serde_json::to_vec(body).map_err(|error| error.to_string())?.into());
        }
        let response = self
            .0
            .execute(request, &http_channel_label(method.as_str(), path))
            .await
            .map_err(|error| format!("cannot reach the Tender daemon (is `tender serve` running?): {error}"))?;
        if response.status().is_success() {
            serde_json::from_slice(response.body()).map_err(|error| format!("unexpected answer from the daemon: {error}"))
        } else {
            let error: ErrorBody = serde_json::from_slice(response.body()).unwrap_or_else(|_| ErrorBody {
                code: response.status().as_str().into(),
                message: String::from_utf8_lossy(response.body()).into(),
            });
            Err(format!("{}: {}", error.code, error.message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Whatever a name holds, the far shell sees it as one literal word.
    #[test]
    fn quoted_values_stay_one_shell_word() {
        for value in ["plain", "with space", "it's", "$(touch /tmp/x)", "'; rm -rf ~; '", ""] {
            let output = std::process::Command::new("sh").args(["-c", &format!("printf %s {}", quote(value))]).output().expect("sh");
            assert_eq!(String::from_utf8(output.stdout).expect("UTF-8"), value);
        }
    }

    #[test]
    fn routes_read_as_written() {
        assert_eq!(route(&None), "not followed");
        assert_eq!(route(&Some(PeerRoute { ssh: None, socket: "/run/peer".into() })), "/run/peer");
        assert_eq!(route(&Some(PeerRoute { ssh: Some("me@kiwi".into()), socket: "/run/peer".into() })), "ssh me@kiwi /run/peer");
    }

    // An SSH destination needs the far socket too; pairing learns it instead.
    #[test]
    fn arguments() {
        assert!(Cli::try_parse_from(["tender", "trust", "add", "key", "--ssh", "kiwi"]).is_err());
        let Cli { command: Command::Trust(Trust::Pair { destination, remote_tender, .. }), json: true } =
            Cli::try_parse_from(["tender", "trust", "pair", "kiwi", "--json"]).expect("pair")
        else {
            panic!("pair")
        };
        assert_eq!((destination.as_str(), remote_tender.as_str()), ("kiwi", "tender"));
    }
}
