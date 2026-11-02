//! The `qa` start and stop fragments run under `bash` (SPEC-qa.md, `qa-api`;
//! #998): `start-app.sh` starts the declared command in its own session in the
//! background, writes the PID file and the log; `stop-app.sh` ends the whole
//! process group and tails the log on failure. The fixture server is
//! `python3 -m http.server` on a free port; nothing is downloaded.
//!
//! The runners (Linux) have util-linux `setsid`; macOS has none. Where the host
//! lacks it, the tests put a stand-in on PATH that does what util-linux does for
//! a process that is not a group leader: `POSIX::setsid()` then `exec`.
mod common;

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const FRAGMENTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/qa/fragments");
const START: &str = include_str!("../../../templates/qa/fragments/start-app.sh");
const STOP: &str = include_str!("../../../templates/qa/fragments/stop-app.sh");

/// How long a test waits for its fixture to be up (a loaded machine is slow to
/// start Python); the spec's own limits (gone within 6 s, KILL after 5 s) are
/// asserted separately.
const SETUP: Duration = Duration::from_secs(30);

const PERL_SETSID: &str = "#!/usr/bin/perl\nuse POSIX ();\nPOSIX::setsid() or die \"setsid: $!\\n\";\nexec { $ARGV[0] } @ARGV or die \"setsid: $ARGV[0]: $!\\n\";\n";

/// A work directory, a `QA_TMP` and the PATH the fragments run with. Dropping it
/// kills whatever group a test left behind.
struct Fixture {
    dir: TempDir,
    path: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let mut path = std::env::var("PATH").unwrap();
        let has_setsid = Command::new("bash")
            .args(["-c", "command -v setsid"])
            .output()
            .unwrap()
            .status
            .success();
        if !has_setsid {
            let bin = dir.path().join("bin");
            fs::create_dir(&bin).unwrap();
            common::write_executable(&bin.join("setsid"), PERL_SETSID);
            path = format!("{}:{path}", bin.display());
        }
        fs::create_dir(dir.path().join("work")).unwrap();
        Self { dir, path }
    }

    fn work(&self) -> PathBuf {
        self.dir.path().join("work")
    }

    fn qa_tmp(&self) -> PathBuf {
        self.dir.path().join("qa")
    }

    fn run(&self, fragment: &str, env: &[(&str, &str)]) -> Output {
        let mut command = Command::new("bash");
        command
            .arg(Path::new(FRAGMENTS).join(fragment))
            .current_dir(self.work())
            .env("PATH", &self.path)
            .env_remove("QA_START")
            .env_remove("QA_NAME")
            .env_remove("QA_TMP")
            .env_remove("QA_FAILED")
            .env_remove("RUNNER_TEMP");
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("bash is on PATH")
    }

    fn start(&self, name: &str, start: &str) -> Output {
        let tmp = self.qa_tmp();
        self.run(
            "start-app.sh",
            &[
                ("QA_START", start),
                ("QA_NAME", name),
                ("QA_TMP", tmp.to_str().unwrap()),
            ],
        )
    }

    fn stop(&self, name: &str, failed: bool) -> Output {
        let tmp = self.qa_tmp();
        let mut env = vec![("QA_NAME", name), ("QA_TMP", tmp.to_str().unwrap())];
        if failed {
            env.push(("QA_FAILED", "1"));
        }
        self.run("stop-app.sh", &env)
    }

    fn pid(&self, name: &str) -> String {
        fs::read_to_string(self.qa_tmp().join(format!("{name}.pid")))
            .unwrap()
            .trim()
            .to_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in ["api", "web"] {
            if let Ok(pid) = fs::read_to_string(self.qa_tmp().join(format!("{name}.pid"))) {
                let _ = Command::new("bash")
                    .args(["-c", "kill -KILL -- -\"$1\" 2>/dev/null", "_", pid.trim()])
                    .status();
            }
        }
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn alive(pid: &str) -> bool {
    Command::new("bash")
        .args(["-c", "kill -0 \"$1\" 2>/dev/null", "_", pid])
        .status()
        .unwrap()
        .success()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Polls `until` every 50 ms for at most `limit`; the test-side wait for a
/// background process, never part of a fragment.
fn wait_for(limit: Duration, mut until: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if until() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    until()
}

fn get(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .ok()?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer).ok()?;
    Some(answer)
}

/// A server whose leader is `bash` and whose child is the Python process; the
/// child's PID lands in `child.pid` in the work directory.
fn server(port: u16) -> String {
    format!("python3 -m http.server {port} --bind 127.0.0.1 & echo $! > child.pid; wait")
}

fn child(fx: &Fixture) -> String {
    let file = fx.work().join("child.pid");
    assert!(wait_for(SETUP, || file.exists()));
    fs::read_to_string(file).unwrap().trim().to_owned()
}

#[test]
fn start_writes_the_pid_file_and_the_server_answers() {
    let fx = Fixture::new();
    let port = free_port();

    let output = fx.start("api", &server(port));

    assert!(output.status.success(), "{output:?}");
    let pid = fx.pid("api");
    let log = fx.qa_tmp().join("api.log");
    assert_eq!(
        stdout(&output),
        format!("start: api pid {pid} log {}\n", log.display())
    );
    assert!(log.is_file());
    assert!(
        wait_for(SETUP, || get(port)
            .is_some_and(|a| a.starts_with("HTTP/1.0 200"))),
        "the server never answered; log: {}",
        fs::read_to_string(&log).unwrap()
    );
    assert!(alive(&pid));
}

#[test]
fn stop_ends_the_leader_and_its_child() {
    let fx = Fixture::new();
    let port = free_port();
    assert!(fx.start("api", &server(port)).status.success());
    let (leader, child) = (fx.pid("api"), child(&fx));
    assert!(wait_for(SETUP, || get(port).is_some()));

    let output = fx.stop("api", false);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        stdout(&output),
        format!("stop: api pid {leader} group ended\n")
    );
    assert!(wait_for(Duration::from_secs(6), || !alive(&leader) && !alive(&child)));
}

#[test]
fn a_group_that_ignores_term_is_killed_after_five_seconds() {
    let fx = Fixture::new();
    let start = "trap '' TERM; sleep 300 & echo $! > child.pid; wait";
    assert!(fx.start("web", start).status.success());
    let (leader, child) = (fx.pid("web"), child(&fx));

    let begun = Instant::now();
    let output = fx.stop("web", false);
    let took = begun.elapsed();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        stdout(&output),
        format!(
            "stop: web pid {leader} ignored TERM for 5 s; sent KILL\nstop: web pid {leader} group ended\n"
        )
    );
    assert!(took >= Duration::from_secs(5), "{took:?}");
    assert!(took < Duration::from_secs(8), "{took:?}");
    assert!(!alive(&leader) && !alive(&child));
}

/// How many polls may start once 5 s have passed since the wait began. Each
/// poll here costs at least 0.2 s, so 50 counted polls (#1307) start at least
/// 25 of their polls after the 5 s; a wall-clock deadline starts only the polls
/// that run before the script sees its deadline gone. The bound counts polls,
/// not seconds, so a slow host does not move it: 20 runs at load 92-129 on 18
/// cores saw at most 1, while the elapsed time reached 8.5 s (#1332).
const LATE_POLLS: usize = 10;

/// The 5 s before KILL are wall-clock time, not 50 polls: on a loaded host
/// (a 3-vCPU macOS runner at load 10) every poll costs a slow fork and exec,
/// and counted polls stretched the wait to 9.4 s (#1307). Here every `sleep`
/// starts 0.1 s late and records when it started; the test counts the polls
/// that start after 5 s instead of bounding the elapsed time, which a loaded
/// host stretches (#1332). A script that keeps polling is killed by the fake
/// `sleep` at its 11th late poll, so it fails instead of hanging.
#[test]
fn the_wait_before_kill_is_five_seconds_however_slow_each_poll_is() {
    let mut fx = Fixture::new();
    let bin = fx.dir.path().join("slow-bin");
    fs::create_dir(&bin).unwrap();
    let events = fx.dir.path().join("sleeps");
    let real_sleep = Command::new("bash")
        .args(["-c", "command -v sleep"])
        .output()
        .unwrap();
    let real_sleep = String::from_utf8(real_sleep.stdout).unwrap();
    // Each line is `<start time> <argument>`; the wait begins with the first
    // `sleep` after the leader's `sleep 300`.
    common::write_executable(
        &bin.join("sleep"),
        &format!(
            r#"#!/usr/bin/env bash
'{sleep}' 0.1
now="$(perl -MTime::HiRes=time -e 'printf "%.3f", time')"
echo "$now $1" >> '{events}'
late="$(awk '$2 != 300 && t0 == "" {{ t0 = $1 }} $2 == "0.1" && $1 >= t0 + 5 {{ n++ }} END {{ print n + 0 }}' '{events}')"
if [ "$late" -gt {LATE_POLLS} ]; then
  echo "more than {LATE_POLLS} polls after 5 s; killed the script" >> '{events}'
  kill -KILL "$PPID"
fi
exec '{sleep}' "$@"
"#,
            sleep = real_sleep.trim(),
            events = events.display(),
        ),
    );
    fx.path = format!("{}:{}", bin.display(), fx.path);
    let start = "trap '' TERM; sleep 300 & echo $! > child.pid; wait";
    assert!(fx.start("web", start).status.success());
    let (leader, child) = (fx.pid("web"), child(&fx));

    let begun = Instant::now();
    let output = fx.stop("web", false);
    let took = begun.elapsed();

    let log = fs::read_to_string(&events).unwrap();
    assert!(output.status.success(), "{output:?}\n{log}");
    assert_eq!(
        stdout(&output),
        format!(
            "stop: web pid {leader} ignored TERM for 5 s; sent KILL\nstop: web pid {leader} group ended\n"
        )
    );
    let sleeps: Vec<(f64, &str)> = log
        .lines()
        .map(|line| {
            let (at, arg) = line.split_once(' ').unwrap();
            (at.parse().unwrap(), arg)
        })
        .filter(|(_, arg)| *arg != "300")
        .collect();
    let begin = sleeps.first().unwrap().0;
    let late = sleeps
        .iter()
        .filter(|(at, arg)| *arg == "0.1" && *at >= begin + 5.0)
        .count();
    assert!(late <= LATE_POLLS, "{late} polls after 5 s:\n{log}");
    assert!(took >= Duration::from_secs(5), "{took:?}");
    assert!(!alive(&leader) && !alive(&child));
}

#[test]
fn a_failed_run_prints_exactly_the_last_fifty_lines_of_the_log() {
    let fx = Fixture::new();
    let start = "for i in $(seq 1 120); do echo line-$i; done; sleep 300";
    assert!(fx.start("api", start).status.success());
    let log = fx.qa_tmp().join("api.log");
    assert!(wait_for(SETUP, || fs::read_to_string(&log)
        .unwrap()
        .lines()
        .count()
        == 120));
    let leader = fx.pid("api");

    let output = fx.stop("api", true);

    assert!(output.status.success(), "{output:?}");
    let expected: Vec<String> = (71..=120).map(|i| format!("line-{i}")).collect();
    let text = stdout(&output);
    let tail: Vec<&str> = text.lines().filter(|l| l.starts_with("line-")).collect();
    assert_eq!(tail, expected);
    assert_eq!(
        text.lines().next().unwrap(),
        format!("stop: api pid {leader} group ended")
    );
    assert_eq!(
        text.lines().nth(1).unwrap(),
        format!("::group::qa: last 50 lines of {}", log.display())
    );
    assert_eq!(text.lines().last().unwrap(), "::endgroup::");
}

#[test]
fn a_passed_run_prints_no_log() {
    let fx = Fixture::new();
    assert!(
        fx.start("api", "echo secret-free-noise; sleep 300")
            .status
            .success()
    );
    let leader = fx.pid("api");

    let output = fx.stop("api", false);

    assert_eq!(
        stdout(&output),
        format!("stop: api pid {leader} group ended\n")
    );
}

#[test]
fn stop_succeeds_when_the_group_is_already_gone() {
    let fx = Fixture::new();
    assert!(fx.start("api", "exit 0").status.success());
    let leader = fx.pid("api");
    assert!(wait_for(SETUP, || !alive(&leader)));

    let output = fx.stop("api", false);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        stdout(&output),
        format!("stop: api pid {leader} already gone\n")
    );
}

#[test]
fn qa_tmp_defaults_to_the_runner_temp() {
    let fx = Fixture::new();
    let runner_temp = fx.dir.path().join("runner");
    fs::create_dir(&runner_temp).unwrap();
    let env = [
        ("QA_START", "sleep 300"),
        ("QA_NAME", "web"),
        ("RUNNER_TEMP", runner_temp.to_str().unwrap()),
    ];

    let output = fx.run("start-app.sh", &env);

    assert!(output.status.success(), "{output:?}");
    let pid_file = runner_temp.join("qa/web.pid");
    let pid = fs::read_to_string(&pid_file).unwrap();
    let stop = fx.run(
        "stop-app.sh",
        &[
            ("QA_NAME", "web"),
            ("RUNNER_TEMP", runner_temp.to_str().unwrap()),
        ],
    );
    assert!(stop.status.success(), "{stop:?}");
    assert!(!alive(pid.trim()));
}

fn refusal(output: &Output, line: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(stdout(output), format!("{line}\n"));
}

#[test]
fn start_refuses_a_missing_or_unknown_variable() {
    let fx = Fixture::new();
    let tmp = fx.qa_tmp();
    let tmp = tmp.to_str().unwrap();

    refusal(
        &fx.run("start-app.sh", &[("QA_NAME", "api"), ("QA_TMP", tmp)]),
        "::error::qa: start-app.sh needs QA_START",
    );
    refusal(
        &fx.run("start-app.sh", &[("QA_START", "sleep 1"), ("QA_TMP", tmp)]),
        "::error::qa: start-app.sh needs QA_NAME",
    );
    refusal(
        &fx.run(
            "start-app.sh",
            &[("QA_START", "sleep 1"), ("QA_NAME", "api")],
        ),
        "::error::qa: start-app.sh needs QA_TMP or RUNNER_TEMP",
    );
    refusal(
        &fx.run(
            "start-app.sh",
            &[("QA_START", "sleep 1"), ("QA_NAME", "db"), ("QA_TMP", tmp)],
        ),
        "::error::qa: start-app.sh QA_NAME must be api or web, got db",
    );
    assert!(!fx.qa_tmp().exists(), "a refusal starts nothing");
}

#[test]
fn stop_refuses_a_missing_pid_file() {
    let fx = Fixture::new();
    let tmp = fx.qa_tmp();

    refusal(
        &fx.stop("api", false),
        &format!(
            "::error::qa: stop-app.sh found no {}; nothing was started",
            tmp.join("api.pid").display()
        ),
    );
}

#[test]
fn both_fragments_parse_and_are_strict() {
    for (name, text) in [("start-app.sh", START), ("stop-app.sh", STOP)] {
        let syntax = Command::new("bash")
            .arg("-n")
            .arg(Path::new(FRAGMENTS).join(name))
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&syntax.stderr)
        );
        assert!(text.starts_with("#!/usr/bin/env bash\n"), "{name}");
        assert!(text.contains("\nset -euo pipefail\n"), "{name}");
        for forbidden in ["|| true", "continue-on-error", "--update-snapshots"] {
            assert!(!text.contains(forbidden), "{name} contains {forbidden}");
        }
    }
}
