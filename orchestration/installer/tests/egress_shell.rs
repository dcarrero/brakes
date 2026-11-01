//! The egress step (`templates/agent-guardrails/egress.sh`; SPEC-agent-guardrails.md,
//! "Egress allowlist", as built #971, after the security review of #1084) under
//! `bash`, as the golden renders it, with fakes on `PATH` for every system command it
//! runs (`sudo`, `useradd`, `id`, `chmod`, `iptables`, `ip6tables`, `dig`, `curl`,
//! `setfacl`, `tee`, `systemctl`, `getent`, `resolvectl`, `timeout`, `test`): the
//! rules it writes, in order, and every way it refuses to let the model start. The
//! real runs on both runner kinds are linked from the PR.
use brakes::auditor::workflows;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/agent-guardrails/goldens/cross-review-claude.yml"
);

/// The `run:` and `env:` of the first egress step of `cross-review-model`.
fn egress_step() -> (String, BTreeMap<String, String>) {
    let wf = workflows::parse(&fs::read_to_string(GOLDEN).unwrap()).unwrap();
    let step = wf
        .job("cross-review-model")
        .unwrap()
        .steps
        .iter()
        .find(|s| s.env.contains_key("EGRESS_USER"))
        .expect("an egress step")
        .clone();
    (step.run.unwrap(), step.env)
}

fn stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Fakes that log to `$LOG`. Switches, all off by default: `BLOCKED_OPEN` (the
/// blocked URL answers), `PROBE_CODE` (what the probe answers, 405 by default),
/// `DNS_OPEN` (getent/resolvectl/dig resolve for the model's user), `UDP_OPEN`,
/// `USER_SUDO`, `USER_SUDO_LIST`, `GROUPS_OF` (the user's groups), `DOCKER_WRITABLE`.
fn fakes(dir: &Path) {
    stub(
        dir,
        "sudo",
        r#"echo "sudo $*" >>"$LOG"
if [ "$1" = "-u" ]; then user=$2; shift 2; [ "$1" = "-H" ] && shift; [ "$1" = "--" ] && shift
  AS_USER=$user exec "$@"; fi
if [ "$1" = "-n" ] && [ -n "${AS_USER:-}" ]; then
  [ "$2" = "-l" ] && { [ "${USER_SUDO_LIST:-0}" = 1 ]; exit; }
  [ "${USER_SUDO:-0}" = 1 ]; exit; fi
exec "$@""#,
    );
    stub(
        dir,
        "useradd",
        r#"echo "useradd $*" >>"$LOG"; touch "$STATE/user""#,
    );
    stub(
        dir,
        "id",
        r#"[ -f "$STATE/user" ] || exit 1
case "$1" in -u) echo 1002 ;; -Gn) echo "${GROUPS_OF:-agent-model}" ;; *) echo "uid=1002($1)" ;; esac"#,
    );
    for name in ["chmod", "iptables", "ip6tables", "setfacl", "systemctl"] {
        stub(dir, name, &format!(r#"echo "{name} $*" >>"$LOG""#));
    }
    stub(dir, "tee", r#"echo "tee $* <<$(cat)" >>"$LOG""#);
    stub(
        dir,
        "dig",
        r#"if [ -n "${AS_USER:-}" ]; then [ "${DNS_OPEN:-0}" = 1 ]; exit; fi
case "$3" in
registry.npmjs.org) [ "$2" = A ] && printf 'registry.npmjs.org.cdn.example.\n104.16.1.34\n104.16.2.34\n' ;;
*) exit 0 ;;
esac"#,
    );
    for name in ["getent", "resolvectl"] {
        stub(
            dir,
            name,
            &format!(
                r#"echo "{name} as=${{AS_USER:-runner}} $*" >>"$LOG"; [ "${{DNS_OPEN:-0}}" = 1 ]"#
            ),
        );
    }
    stub(
        dir,
        "timeout",
        r#"shift; if [ "$1" = bash ]; then echo "udp as=${AS_USER:-runner}" >>"$LOG"; [ "${UDP_OPEN:-0}" = 1 ]; exit; fi
exec "$@""#,
    );
    stub(
        dir,
        "test",
        r#"case "$*" in *docker.sock*) [ "${DOCKER_WRITABLE:-0}" = 1 ]; exit ;; esac; builtin test "$@""#,
    );
    stub(
        dir,
        "curl",
        r#"echo "curl as=${AS_USER:-runner} $*" >>"$LOG"
url="${@: -1}"
if [ "$url" = "https://example.com" ]; then [ "${BLOCKED_OPEN:-0}" = 1 ]; exit; fi
printf '%s' "${PROBE_CODE:-405}""#,
    );
}

struct Run {
    ok: bool,
    stdout: String,
    log: Vec<String>,
}

fn run(env: &[(&str, &str)]) -> Run {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    let state = temp.path().join("state");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&state).unwrap();
    fakes(&bin);
    if env.iter().any(|(k, _)| *k == "EGRESS_MODE") {
        // A check runs after the limit: the user exists.
        fs::write(state.join("user"), "").unwrap();
    }
    let log = temp.path().join("log");
    let (script, step_env) = egress_step();
    assert_eq!(step_env["EGRESS_USER"], "agent-model");
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
        .arg(script)
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("LOG", &log)
        .env("STATE", &state)
        .env("EGRESS_USER", "agent-model")
        .env_remove("EGRESS_HOSTS")
        .env_remove("EGRESS_PROBE_URL")
        .env_remove("EGRESS_MODE");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        log: fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect(),
    }
}

fn position(log: &[String], line: &str) -> usize {
    log.iter()
        .position(|l| l == line)
        .unwrap_or_else(|| panic!("{line:?} not in\n{}", log.join("\n")))
}

#[test]
fn it_confines_the_model_user_alone_without_dns_and_proves_it() {
    let r = run(&[]);
    assert!(r.ok, "{}\n{}", r.stdout, r.log.join("\n"));
    let order = [
        "useradd --create-home --shell /bin/bash agent-model",
        "chmod 755 /home/agent-model",
        "iptables -N AGENT-EGRESS",
        "iptables -A AGENT-EGRESS -o lo -p udp --dport 53 -j REJECT",
        "iptables -A AGENT-EGRESS -o lo -p tcp --dport 53 -j REJECT",
        "iptables -A AGENT-EGRESS -o lo -j ACCEPT",
        "iptables -A AGENT-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "ip6tables -N AGENT-EGRESS",
        "ip6tables -A AGENT-EGRESS -o lo -p udp --dport 53 -j REJECT",
        "ip6tables -A AGENT-EGRESS -o lo -j ACCEPT",
        "ip6tables -A AGENT-EGRESS -d fe80::/10 -p ipv6-icmp --icmpv6-type 133 -m hl --hl-eq 255 -j ACCEPT",
        "ip6tables -A AGENT-EGRESS -d ff02::/16 -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT",
        "iptables -A AGENT-EGRESS -j REJECT --reject-with icmp-admin-prohibited",
        "ip6tables -A AGENT-EGRESS -j REJECT --reject-with icmp6-adm-prohibited",
        "iptables -I OUTPUT 1 -m owner --uid-owner 1002 -j AGENT-EGRESS",
        "ip6tables -I OUTPUT 1 -m owner --uid-owner 1002 -j AGENT-EGRESS",
        "curl as=agent-model --silent --max-time 10 --output /dev/null https://example.com",
        "getent as=agent-model hosts example.com",
        "resolvectl as=agent-model query example.com",
        "udp as=agent-model",
    ];
    let mut last = 0;
    for line in order {
        let at = position(&r.log, line);
        assert!(at >= last, "{line:?} out of order in\n{}", r.log.join("\n"));
        last = at;
    }
    // No DNS rule toward any resolver, no rule for every process, no policy change,
    // no ICMPv6 beyond the link.
    assert!(!r.log.iter().any(|l| l.contains("--dport 53 -j ACCEPT")));
    assert!(!r.log.iter().any(|l| l.contains("-P OUTPUT")));
    assert!(
        !r.log
            .iter()
            .any(|l| l.contains("-I OUTPUT") && !l.contains("--uid-owner"))
    );
    assert!(
        !r.log
            .iter()
            .any(|l| l.contains("icmpv6-type") && !l.contains("--hl-eq 255"))
    );
    assert!(
        r.stdout.contains("egress: agent-model confined; https://example.com refused, DNS refused, UDP refused; sudo refused; groups agent-model"),
        "{}",
        r.stdout
    );
}

#[test]
fn an_allowed_host_goes_to_etc_hosts_and_gets_its_addresses_alone() {
    let r = run(&[("EGRESS_HOSTS", "registry.npmjs.org")]);
    assert!(r.ok, "{}\n{}", r.stdout, r.log.join("\n"));
    position(&r.log, "tee -a /etc/hosts <<104.16.1.34 registry.npmjs.org");
    position(&r.log, "iptables -A AGENT-EGRESS -d 104.16.1.34 -j ACCEPT");
    position(&r.log, "iptables -A AGENT-EGRESS -d 104.16.2.34 -j ACCEPT");
    assert!(
        !r.log.iter().any(|l| l.contains("cdn.example")),
        "a CNAME is not an address"
    );
}

#[test]
fn the_check_mode_proves_again_through_the_probe_and_writes_nothing() {
    let r = run(&[
        ("EGRESS_MODE", "check"),
        ("EGRESS_PROBE_URL", "http://127.0.0.1:4100/v1/messages"),
    ]);
    assert!(r.ok, "{}\n{}", r.stdout, r.log.join("\n"));
    assert!(
        !r.log.iter().any(|l| l.starts_with("iptables")
            || l.starts_with("ip6tables")
            || l.starts_with("useradd")
            || l.starts_with("tee")),
        "{}",
        r.log.join("\n")
    );
    position(
        &r.log,
        "curl as=agent-model --silent --max-time 20 --output /dev/null --write-out %{http_code} http://127.0.0.1:4100/v1/messages",
    );
    assert!(
        r.stdout
            .contains("http://127.0.0.1:4100/v1/messages answered 405"),
        "{}",
        r.stdout
    );
}

fn refused(env: &[(&str, &str)], message: &str) {
    let r = run(env);
    assert!(!r.ok, "{env:?} passed:\n{}", r.stdout);
    assert!(
        r.stdout.contains(&format!("::error::egress: {message}")),
        "{}",
        r.stdout
    );
}

#[test]
fn it_refuses_every_way_out_it_can_prove() {
    refused(
        &[("BLOCKED_OPEN", "1")],
        "https://example.com is reachable as agent-model; its outbound traffic is not closed",
    );
    refused(
        &[("DNS_OPEN", "1")],
        "agent-model resolves names through the system resolver; DNS is a channel out",
    );
    refused(
        &[("UDP_OPEN", "1")],
        "agent-model can send UDP out; its outbound traffic is not closed",
    );
    refused(
        &[("USER_SUDO", "1")],
        "agent-model can use sudo; it could lift the limit",
    );
    refused(
        &[("USER_SUDO_LIST", "1")],
        "agent-model can use sudo; it could lift the limit",
    );
    refused(
        &[("GROUPS_OF", "agent-model docker")],
        "agent-model is in groups agent-model docker; it must be in its own group only",
    );
    refused(
        &[
            ("EGRESS_PROBE_URL", "http://127.0.0.1:4100/v1/messages"),
            ("PROBE_CODE", "000"),
        ],
        "http://127.0.0.1:4100/v1/messages is unreachable as agent-model",
    );
    refused(
        &[("EGRESS_HOSTS", "nowhere.invalid")],
        "cannot resolve nowhere.invalid",
    );
}
