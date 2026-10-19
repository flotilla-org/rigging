use super::{ChannelLabel, ChannelLabeler, ChannelRequest, CommandOutput, CommandRunner, DefaultLabeler, Masks, NoExtra, ReplayMode};
use super::{
    Interaction as GenericInteraction, InteractionLog as GenericInteractionLog, Recorder as GenericRecorder,
    RecordingRunner as GenericRecordingRunner, ReplayHttpClient as GenericReplayHttpClient, ReplayRunner as GenericReplayRunner,
    Round as GenericRound, Session as GenericSession,
};
use std::{path::Path, sync::Arc};
type Interaction = GenericInteraction<NoExtra>;
type InteractionLog = GenericInteractionLog<NoExtra>;
type Session = GenericSession<NoExtra>;
type Recorder = GenericRecorder<NoExtra>;
type Round = GenericRound<NoExtra>;
type ReplayRunner = GenericReplayRunner<NoExtra>;
type RecordingRunner = GenericRecordingRunner<NoExtra>;
type ReplayHttpClient = GenericReplayHttpClient<NoExtra>;
use super::test_runner;
type RoundLog = super::RoundLog<NoExtra>;
macro_rules! run {
    ($runner:expr, $cmd:expr, $args:expr, $cwd:expr) => {
        $runner.run($cmd, $args, $cwd, &rigging_process::command_channel_label($cmd, $args)).await
    };
    ($runner:expr, $cmd:expr, $args:expr, $cwd:expr, $labeler:expr) => {
        $runner.run($cmd, $args, $cwd, &rigging_process::command_channel_label_with::<true, _>($cmd, $args, &$labeler)).await
    };
}

#[test]
fn masks_substitute_and_reverse() {
    let mut masks = Masks::new();
    masks.add("/Users/bob/dev/repo", "{repo}");
    masks.add("/Users/bob", "{home}");

    assert_eq!(masks.mask("/Users/bob/dev/repo/src"), "{repo}/src");
    assert_eq!(masks.unmask("{repo}/src"), "/Users/bob/dev/repo/src");
    // Ordering matters: longer match first
    assert_eq!(masks.mask("/Users/bob/.config"), "{home}/.config");
}

#[test]
fn replay_session_serves_in_order() {
    let log = InteractionLog {
        interactions: vec![Interaction::Command {
            label: None,
            cmd: "git".into(),
            args: vec!["status".into()],
            cwd: "{repo}".into(),
            stdout: Some("ok\n".into()),
            stderr: None,
            exit_code: Some(0),
            error: None,
        }],
    };

    let yaml = serde_norway::to_string(&log).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.yaml");
    std::fs::write(&path, &yaml).unwrap();

    let mut masks = Masks::new();
    masks.add("/real/repo", "{repo}");
    let session = Session::replaying(&path, masks);

    let interaction = session.next(&ChannelLabel::Command("git status".into()));
    match interaction {
        Interaction::Command { cmd, cwd, .. } => {
            assert_eq!(cmd, "git");
            assert_eq!(cwd, "/real/repo");
        }
        _ => panic!("expected command"),
    }
    session.assert_complete();
}

#[tokio::test]
async fn record_then_replay() {
    use super::testing::MockRunner;

    let dir = tempfile::tempdir().unwrap();
    let fixture_path = dir.path().join("recorded.yaml");

    // Record phase: use MockRunner as the "real" backend
    {
        let mock = Arc::new(MockRunner::new(vec![Ok("hello\n".into()), Err("not found".into())]));
        let session = Session::recording(&fixture_path, Masks::new());
        let recorder = RecordingRunner::new(session.clone(), mock);

        let r1 = run!(recorder, "echo", &["hello"], Path::new("/tmp"));
        assert!(r1.is_ok());

        let r2 = run!(recorder, "missing", &[], Path::new("/tmp"));
        assert!(r2.is_err());

        session.finish();
    }

    // Replay phase: verify the recorded fixture works
    {
        let session = Session::replaying(&fixture_path, Masks::new());
        let runner = ReplayRunner::new(session.clone());

        let r1 = run!(runner, "echo", &["hello"], Path::new("/tmp"));
        assert_eq!(r1.unwrap(), "hello\n");

        let r2 = run!(runner, "missing", &[], Path::new("/tmp"));
        assert!(r2.is_err());

        session.assert_complete();
    }
}

#[tokio::test]
async fn replay_http_client_round_trip() {
    use rigging_http_client::HttpClient;

    let yaml = r#"
interactions:
  - channel: http
    method: GET
    url: "https://example.test/v1/sessions"
    request_headers:
      authorization: "Bearer token-1"
      anthropic-version: "2023-06-01"
    status: 200
    response_body: '{"data":[]}'
"#;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("http.yaml");
    std::fs::write(&path, yaml).unwrap();

    let session = Session::replaying(&path, Masks::new());
    let client = ReplayHttpClient::new(session.clone());

    let request = rigging_tls::client()
        .get("https://example.test/v1/sessions")
        .header("authorization", "Bearer token-1")
        .header("anthropic-version", "2023-06-01")
        .build()
        .unwrap();

    let label = ChannelLabel::http_from_url("https://example.test/v1/sessions");
    let response = client.execute(request, &label).await.expect("replay should work");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.body().as_ref(), br#"{"data":[]}"#);
    session.assert_complete();
}

#[test]
fn multi_channel_round_allows_any_consumption_order() {
    // Fixture has command and http in same round
    let yaml = r#"
interactions:
  - channel: command
    cmd: git
    args: ["status"]
    cwd: "/repo"
    stdout: "ok\n"
    exit_code: 0
  - channel: http
    method: GET
    url: "https://api.test/v1/sessions"
    status: 200
    response_body: '{"data":[]}'
  - channel: command
    cmd: git
    args: ["log"]
    cwd: "/repo"
    stdout: "abc\n"
    exit_code: 0
"#;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.yaml");
    std::fs::write(&path, yaml).unwrap();

    let session = Session::replaying(&path, Masks::new());

    // Consume http FIRST (before any commands) — this is the key test.
    // With the old linear cursor this would have panicked.
    let http = session.next(&ChannelLabel::Http("api.test".into()));
    assert!(matches!(http, Interaction::Http { .. }));

    // Now consume commands in order
    let cmd1 = session.next(&ChannelLabel::Command("git status".into()));
    match cmd1 {
        Interaction::Command { args, .. } => assert_eq!(args[0], "status"),
        _ => panic!("expected command"),
    }

    let cmd2 = session.next(&ChannelLabel::Command("git log".into()));
    match cmd2 {
        Interaction::Command { args, .. } => assert_eq!(args[0], "log"),
        _ => panic!("expected command"),
    }

    session.finish();
}

#[test]
fn default_labeler_uses_subcommand() {
    let request = ChannelRequest::Command { cmd: "git", args: &["branch", "--list"] };
    assert_eq!(DefaultLabeler.label_for(&request), ChannelLabel::Command("git branch".into()));
}

#[test]
fn default_labeler_no_args_uses_cmd() {
    let request = ChannelRequest::Command { cmd: "git", args: &[] };
    assert_eq!(DefaultLabeler.label_for(&request), ChannelLabel::Command("git".into()));
}

#[test]
fn task_id_overrides_label() {
    use rigging_process::TaskId;
    let request = ChannelRequest::Command { cmd: "git", args: &["rev-list", "--left-right", "--count", "HEAD...main"] };
    assert_eq!(TaskId("trunk-ab").label_for(&request), ChannelLabel::Command("trunk-ab".into()));
}

#[test]
fn round_is_empty() {
    let round = Round::from_interactions(vec![]);
    assert!(round.is_empty());

    let round = Round::from_interactions(vec![Interaction::Command {
        label: None,
        cmd: "git".into(),
        args: vec![],
        cwd: "/repo".into(),
        stdout: None,
        stderr: None,
        exit_code: Some(0),
        error: None,
    }]);
    assert!(!round.is_empty());
}

#[test]
fn recorder_saves_single_round() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("recorded.yaml");

    let recorder = Recorder::new(&path, Masks::new());
    recorder.record(Interaction::Command {
        label: None,
        cmd: "git".into(),
        args: vec!["status".into()],
        cwd: "/repo".into(),
        stdout: Some("ok\n".into()),
        stderr: None,
        exit_code: Some(0),
        error: None,
    });
    recorder.save();

    let content = std::fs::read_to_string(&path).expect("read fixture");
    let round_log: RoundLog = serde_norway::from_str(&content).expect("parse fixture");
    assert_eq!(round_log.rounds.len(), 1);
    assert_eq!(round_log.rounds[0].interactions.len(), 1);
}

#[test]
fn recorder_applies_masks() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("recorded.yaml");

    let mut masks = Masks::new();
    masks.add("/Users/bob/dev/repo", "{repo}");

    let recorder = Recorder::new(&path, masks);
    recorder.record(Interaction::Command {
        label: None,
        cmd: "git".into(),
        args: vec!["status".into()],
        cwd: "/Users/bob/dev/repo".into(),
        stdout: Some("ok\n".into()),
        stderr: None,
        exit_code: Some(0),
        error: None,
    });
    recorder.save();

    let content = std::fs::read_to_string(&path).expect("read fixture");
    assert!(content.contains("{repo}"), "expected masked value in output");
    assert!(!content.contains("/Users/bob/dev/repo"), "expected concrete value to be masked");
}

#[tokio::test]
async fn session_record_then_replay_round_trip() {
    use super::testing::MockRunner;

    let dir = tempfile::tempdir().expect("create temp dir");
    let fixture_path = dir.path().join("round_trip.yaml");

    // Record phase with barriers
    {
        let mock = Arc::new(MockRunner::new(vec![Ok("branch-list\n".into()), Ok("status-ok\n".into())]));
        let session = Session::recording(&fixture_path, Masks::new());
        let runner = RecordingRunner::new(session.clone(), mock);

        let r1 = run!(runner, "git", &["branch"], Path::new("/repo"));
        assert!(r1.is_ok());

        session.barrier();

        let r2 = run!(runner, "git", &["status"], Path::new("/repo"));
        assert!(r2.is_ok());

        session.finish();
    }

    // Replay phase — verify round structure is preserved
    {
        let session = Session::replaying(&fixture_path, Masks::new());
        let runner = ReplayRunner::new(session.clone());

        let r1 = run!(runner, "git", &["branch"], Path::new("/repo"));
        assert_eq!(r1.expect("round 1 replay"), "branch-list\n");

        let r2 = run!(runner, "git", &["status"], Path::new("/repo"));
        assert_eq!(r2.expect("round 2 replay"), "status-ok\n");

        session.assert_complete();
    }
}

#[tokio::test]
async fn concurrent_same_subcommand_with_task_id() {
    use rigging_process::TaskId;

    let yaml = r#"
rounds:
- interactions:
  - channel: command
    label: trunk-ab
    cmd: git
    args: ["rev-list", "--left-right", "--count", "HEAD...main"]
    cwd: /test
    stdout: "2\t3"
    exit_code: 0
  - channel: command
    label: remote-ab
    cmd: git
    args: ["rev-list", "--left-right", "--count", "HEAD...origin/feature"]
    cwd: /test
    stdout: "0\t5"
    exit_code: 0
"#;
    let session = Session::replaying_from_str(yaml, Masks::new());
    let runner = Arc::new(ReplayRunner::new(session.clone()));
    let cwd = Path::new("/test");

    // Consume in REVERSE order — works because TaskId puts them on different channels
    let (remote, trunk) = tokio::join!(
        async { run!(runner, "git", &["rev-list", "--left-right", "--count", "HEAD...origin/feature"], cwd, TaskId("remote-ab")) },
        async { run!(runner, "git", &["rev-list", "--left-right", "--count", "HEAD...main"], cwd, TaskId("trunk-ab")) },
    );

    assert_eq!(remote.unwrap().trim(), "0\t5");
    assert_eq!(trunk.unwrap().trim(), "2\t3");
    session.finish();
}

#[test]
fn replay_mode_defaults_to_replay() {
    // With no env var set (or non-matching value), mode is Replay
    assert_eq!(ReplayMode::parse(""), ReplayMode::Replay);
    assert_eq!(ReplayMode::parse("nonsense"), ReplayMode::Replay);
}

#[test]
fn replay_mode_record() {
    assert_eq!(ReplayMode::parse("record"), ReplayMode::Record);
}

#[test]
fn replay_mode_passthrough() {
    assert_eq!(ReplayMode::parse("passthrough"), ReplayMode::Passthrough);
}

#[test]
fn is_live_true_for_record_and_passthrough() {
    assert!(!ReplayMode::Replay.is_live());
    assert!(ReplayMode::Record.is_live());
    assert!(ReplayMode::Passthrough.is_live());
}

#[test]
fn session_passthrough_finish_is_noop() {
    let session = Session::Passthrough;
    // Should not panic
    session.finish();
}

#[test]
fn session_passthrough_barrier_is_noop() {
    let session = Session::Passthrough;
    session.barrier();
}

#[test]
fn session_passthrough_is_not_recording() {
    let session = Session::Passthrough;
    assert!(!session.is_recording());
}

#[test]
fn session_passthrough_is_live() {
    assert!(!Session::replaying_from_str("interactions: []", Masks::new()).is_live());
    assert!(Session::Passthrough.is_live());
}

#[tokio::test]
async fn test_runner_passthrough_returns_process_runner() {
    // Runs a real subprocess unconditionally — `echo` is universally available
    // and instant, so this is acceptable outside passthrough mode.  The test
    // validates that Session::Passthrough produces a functional runner.
    let session = Session::Passthrough;
    let runner = test_runner(&session);
    let result = runner.run("echo", &["hello"], Path::new("/tmp"), &ChannelLabel::Default).await;
    assert!(result.is_ok());
    assert!(result.unwrap().contains("hello"));
}

#[hegel::test]
fn command_exit_status_survives_record_replay(tc: hegel::TestCase) {
    use hegel::generators as gs;

    use super::testing::MockRunner;

    let label = rigging_process::command_channel_label("pgrep", &["-x", "example-daemon"]);
    let generated = tc.draw(gs::integers::<i32>());
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime").block_on(async {
        let temp = tempfile::tempdir().expect("recording directory");
        for exit_code in [Some(0), Some(1), Some(2), Some(17), Some(generated), None] {
            let path = temp.path().join("command.yaml");
            let session = Session::recording(&path, Masks::new());
            let inner = Arc::new(MockRunner::with_outputs(vec![Ok(CommandOutput {
                stdout: "output\n".into(),
                stderr: "diagnostic\n".into(),
                exit_code,
            })]));
            let recording = RecordingRunner::new(session.clone(), inner);
            let live = recording.run_output("pgrep", &["-x", "example-daemon"], Path::new("/"), &label).await.expect("live");
            session.finish();
            let session = Session::replaying(&path, Masks::new());
            let replay = ReplayRunner::new(session.clone());
            let output = replay.run_output("pgrep", &["-x", "example-daemon"], Path::new("/"), &label).await.expect("replay");
            assert_eq!(output.exit_code, exit_code);
            assert_eq!(output.success(), exit_code == Some(0));
            assert_eq!((output.stdout, output.stderr), (live.stdout, live.stderr));
            session.finish();
            // The string convenience API selects stderr for every failure,
            // including explicit null/no-code termination, and stdout for zero.
            let session = Session::replaying(&path, Masks::new());
            let output = ReplayRunner::new(session.clone()).run("pgrep", &["-x", "example-daemon"], Path::new("/"), &label).await;
            let expected = if exit_code == Some(0) { Ok("output\n".to_string()) } else { Err("diagnostic\n".to_string()) };
            assert_eq!(output, expected);
            session.finish();
        }
    });
}

// Existing integer and omitted status fields remain decodable; an explicit
// null newly represents termination without a numeric exit code.
#[test]
fn legacy_command_exit_status_is_readable() {
    for (field, expected) in [("", Some(0)), ("exit_code: 42\n", Some(42)), ("exit_code: null\n", None)] {
        let yaml = format!("channel: command\ncmd: pgrep\nargs: []\ncwd: /\n{field}");
        let interaction: Interaction = serde_norway::from_str(&yaml).expect("decode command");
        let Interaction::Command { exit_code, .. } = interaction else { panic!("command") };
        assert_eq!(exit_code, expected);
    }
}

// Raw-output execution failures survive recording as errors, rather than an
// exit code 1 that pgrep callers must interpret as a successful empty match.
#[tokio::test]
async fn command_execution_error_survives_record_replay() {
    use super::testing::MockRunner;
    let temp = tempfile::tempdir().expect("recording directory");
    let path = temp.path().join("failure.yaml");
    let label = rigging_process::command_channel_label("pgrep", &["-x", "example-daemon"]);
    let mut masks = Masks::new();
    masks.add("/private/runtime", "{runtime}");
    let session = Session::recording(&path, masks.clone());
    let inner = Arc::new(MockRunner::with_outputs(vec![Err("cannot execute in /private/runtime".into())]));
    let expected =
        RecordingRunner::new(session.clone(), inner).run_output("pgrep", &["-x", "example-daemon"], Path::new("/"), &label).await.err();
    session.finish();
    assert!(!std::fs::read_to_string(&path).expect("recording").contains("/private/runtime"));
    let session = Session::replaying(&path, masks);
    let actual = ReplayRunner::new(session.clone()).run_output("pgrep", &["-x", "example-daemon"], Path::new("/"), &label).await.err();
    assert_eq!(actual, expected);
    assert_eq!(actual.as_deref(), Some("cannot execute in /private/runtime"));
    session.finish();
}
