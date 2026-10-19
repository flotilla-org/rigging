use super::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

// This fake sits at a consumer-owned RPC boundary. Its wire shape deliberately
// includes channel and payload fields rather than wrapping them in an extra tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "channel")]
enum Rpc {
    #[serde(rename = "rpc")]
    Call { label: Option<String>, endpoint: String, body: String, headers: HashMap<String, String> },
}
impl ExtraChannel for Rpc {
    fn channel_label(&self) -> ChannelLabel {
        let Self::Call { label, endpoint, .. } = self;
        ChannelLabel::Extra("rpc".into(), label.as_ref().unwrap_or(endpoint).clone())
    }
    fn transform(&self, map: &dyn Fn(&str) -> String) -> Self {
        let Self::Call { label, endpoint, body, headers } = self;
        Self::Call {
            label: label.clone(),
            endpoint: map(endpoint),
            body: map(body),
            headers: headers.iter().map(|(k, v)| (k.clone(), map(v))).collect(),
        }
    }
}

// Consumer extensions preserve their YAML shape and payload masks, share round
// barriers with built-in channels, and retain FIFO order within each channel.
// Generate empty/boundary payloads, duplicates, explicit/default labels and
// alternating consumption orders. Real filesystem persistence is the boundary.
#[hegel::test]
fn extension_round_trip_preserves_schema_masks_and_order(tc: hegel::TestCase) {
    let count = tc.draw(hegel::generators::integers::<usize>().min_value(1).max_value(8));
    let explicit = tc.draw(hegel::generators::booleans());
    let rpc_first = tc.draw(hegel::generators::booleans());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recording.yaml");
    let mut masks = Masks::new();
    masks.add("/private/root", "{root}");
    let recording: Session<Rpc> = Session::recording(&path, masks.clone());
    let endpoint = "/private/root/endpoint";
    // Labels, including default labels, stay in fixture space (before unmasking).
    let key = if explicit { "task" } else { "{root}/endpoint" };
    let label = ChannelLabel::Extra("rpc".into(), key.into());
    for round in 0..2 {
        for index in 0..count {
            recording.record(Interaction::Extra(Rpc::Call {
                label: explicit.then(|| "task".into()),
                endpoint: endpoint.into(),
                body: format!("/private/root/{round}/{index}"),
                headers: HashMap::from([("meta".into(), "/private/root".into())]),
            }));
            recording.record(Interaction::Command {
                label: None,
                cmd: "tool".into(),
                args: vec![],
                cwd: "/".into(),
                stdout: Some(String::new()),
                stderr: None,
                exit_code: Some(0),
                error: None,
            });
        }
        recording.barrier();
    }
    recording.finish();
    let yaml = std::fs::read_to_string(&path).unwrap();
    assert!(yaml.contains("channel: rpc"));
    assert!(!yaml.contains("/private/root"));
    assert!(!yaml.contains("Extra"));
    let replay: Session<Rpc> = Session::replaying(&path, masks);
    for round in 0..2 {
        let rpc = || {
            for index in 0..count {
                let Interaction::Extra(Rpc::Call { endpoint: actual, body, headers, .. }) = replay.next(&label) else {
                    panic!("expected extension")
                };
                assert_eq!(actual, endpoint);
                assert_eq!(body, format!("/private/root/{round}/{index}"));
                assert_eq!(headers["meta"], "/private/root");
            }
        };
        let commands = || {
            for _ in 0..count {
                assert!(matches!(replay.next(&ChannelLabel::Command("tool".into())), Interaction::Command { .. }));
            }
        };
        if rpc_first {
            rpc();
            commands();
        } else {
            commands();
            rpc();
        }
    }
    replay.finish();
}

// A generic default session must reject unknown channels and malformed built-in
// records instead of silently dropping them or treating them as successful calls.
#[test]
fn unknown_and_malformed_channels_are_rejected() {
    for yaml in [
        "interactions: [{channel: unknown}]",
        "interactions: [{channel: command, cmd: tool}]",
        "interactions: [{channel: http, status: 200}]",
    ] {
        assert!(std::panic::catch_unwind(|| Session::<NoExtra>::replaying_from_str(yaml, Masks::new())).is_err());
    }
}

// Round barriers prohibit consuming an extension from the following round even
// when it has the requested label. A fresh session also detects leftovers.
#[test]
fn extension_obeys_round_barriers_and_completion_checks() {
    let yaml = "rounds:\n- interactions:\n  - {channel: command, cmd: tool, args: [], cwd: /}\n- interactions:\n  - {channel: rpc, label: task, endpoint: endpoint, body: '', headers: {}}\n";
    let replay: Session<Rpc> = Session::replaying_from_str(yaml, Masks::new());
    assert!(std::panic::catch_unwind(|| replay.next(&ChannelLabel::Extra("rpc".into(), "task".into()))).is_err());
    let replay: Session<Rpc> = Session::replaying_from_str(yaml, Masks::new());
    assert!(std::panic::catch_unwind(|| replay.finish()).is_err());
}

// Glue: extension sessions still drive command and HTTP wrappers. One call of
// each exercises generic inference and public collaborators across crate seams.
#[tokio::test]
async fn extended_session_drives_builtin_wrappers() {
    let replay: Session<Rpc> = Session::replaying_from_str(
        "interactions:\n- {channel: command, cmd: tool, args: [], cwd: /, stdout: ok}\n- {channel: http, method: GET, url: 'https://example.com/', status: 204, response_body: ''}\n",
        Masks::new(),
    );
    let runner = test_runner(&replay);
    assert_eq!(rigging_process::run!(runner, "tool", &[], Path::new("/")).unwrap(), "ok");
    let client = test_http_client(&replay);
    let response = rigging_http_client::http_execute!(client, rigging_tls::client().get("https://example.com/").build().unwrap()).unwrap();
    assert_eq!(response.status(), 204);
    replay.finish();
    let _shared: Arc<dyn CommandRunner> = runner;
}

// Generic discovery probes execute in the injected runner environment. Missing,
// relative and empty binary resolutions are rejected; probe failures propagate.
#[tokio::test]
async fn discovery_uses_injected_environment_and_parses_versions() {
    use crate::testing::MockRunner;
    use rigging_process::discovery::{command_version, parse_first_dotted_version, resolve_binary_path, resolve_binary_path_with_marker};
    for (output, expected) in [("/tools/tool\n", Some("/tools/tool")), ("relative/tool", None), ("", None)] {
        let runner = MockRunner::new(vec![Ok(output.into())]);
        assert_eq!(resolve_binary_path(&runner, "tool").await, expected.map(PathBuf::from));
        assert_eq!(
            runner.calls(),
            vec![("sh".into(), vec!["-c".into(), "command -v \"$1\"".into(), "rigging-binary-discovery".into(), "tool".into()])]
        );
    }
    // Glue: caller markers are opaque argv data, including empty and shell syntax.
    for marker in ["", "legacy-binary-discovery", "marker; '$0' \"quoted\""] {
        let runner = MockRunner::new(vec![Ok("/tools/tool\n".into())]);
        assert_eq!(resolve_binary_path_with_marker(&runner, "tool", marker).await, Some(PathBuf::from("/tools/tool")));
        assert_eq!(runner.calls()[0].1[2], marker);
    }
    let runner = MockRunner::new(vec![Err("missing".into())]);
    assert!(resolve_binary_path(&runner, "tool").await.is_none());
    for (output, expected) in [
        ("tool 2.43.0\n", Some("2.43.0")),
        ("1.0.20 (Tool)", Some("1.0.20")),
        ("no version", None),
        ("v42", None),
        ("42.", None),
        ("", None),
    ] {
        let runner = MockRunner::new(vec![Ok(output.into())]);
        assert_eq!(command_version(&runner, "tool", &["--version"], parse_first_dotted_version).await.unwrap().as_deref(), expected);
        assert_eq!(runner.calls(), vec![("tool".into(), vec!["--version".into()])]);
    }
    let runner = MockRunner::new(vec![Err("missing".into())]);
    assert_eq!(command_version(&runner, "tool", &[], parse_first_dotted_version).await, Err("missing".into()));
}

// The real reqwest executor preserves status, headers and binary bodies. Its
// streaming file path writes successful bodies and preserves files on HTTP
// errors. The stand-in changes only the authority, retaining path/query/body.
#[tokio::test]
async fn http_executor_and_standin_preserve_the_request_and_response() {
    use crate::http_contract::StandIn;
    use axum::{
        Router,
        body::Bytes,
        http::Uri,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use rigging_http_client::{HttpClient, ReqwestHttpClient};
    let router = Router::new()
        .route(
            "/echo",
            post(|uri: Uri, headers: HeaderMap, body: Bytes| async move {
                assert_eq!(uri.query(), Some("key=value"));
                assert_eq!(headers["x-contract"], "required");
                (StatusCode::CREATED, [("x-response", "present")], body)
            }),
        )
        .route("/fail", axum::routing::get(|| async { (StatusCode::FORBIDDEN, "denied") }));
    let standin = StandIn::start("https://service.example", router).await;
    let payload = vec![0, 128, 255, 1];
    let request = rigging_tls::client()
        .post("https://service.example/echo?key=value")
        .header("x-contract", "required")
        .body(payload.clone())
        .build()
        .unwrap();
    let response = standin.http.execute(request, &ChannelLabel::Default).await.unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()["x-response"], "present");
    assert_eq!(response.body().as_ref(), payload);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("body");
    let client = ReqwestHttpClient::new();
    let request = rigging_tls::client()
        .post(standin.url.join("echo?key=value").unwrap())
        .header("x-contract", "required")
        .body(payload.clone())
        .build()
        .unwrap();
    assert_eq!(client.execute_to_file(request, &ChannelLabel::Default, &path).await.unwrap(), 201);
    assert_eq!(std::fs::read(&path).unwrap(), payload);
    let request = rigging_tls::client().get(standin.url.join("fail").unwrap()).build().unwrap();
    let response = client.execute(request, &ChannelLabel::Default).await.unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(response.body().as_ref(), b"denied");
    let request = rigging_tls::client().get(standin.url.join("fail").unwrap()).build().unwrap();
    assert_eq!(client.execute_to_file(request, &ChannelLabel::Default, &path).await.unwrap(), 403);
    assert_eq!(std::fs::read(path).unwrap(), payload);
}
