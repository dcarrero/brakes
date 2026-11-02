//! The release workflow the import ships (#1278): a version tag builds the three
//! targets on GitHub-hosted runners, attests them and attaches them to the release,
//! with the least privilege per job. Here it is the `export/` overlay; in the
//! exported tree (which never carries `export/`) it is `.github/workflows/release.yml`.
use brakes::auditor::workflows::{Permissions, Workflow, parse};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn release() -> (String, Workflow) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = if root.join("export").is_dir() {
        root.join("export/.github/workflows/release.yml")
    } else {
        root.join(".github/workflows/release.yml")
    };
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let workflow = parse(&text).unwrap();
    (text, workflow)
}

fn scopes(pairs: &[(&str, &str)]) -> Option<Permissions> {
    Some(Permissions::Scopes(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
    ))
}

#[test]
fn a_version_tag_is_the_only_trigger() {
    let (text, workflow) = release();
    assert_eq!(workflow.triggers, ["push"]);
    assert!(text.contains("tags: [\"v*\"]"), "{text}");
    assert!(!text.contains("pull_request_target"));
}

#[test]
fn only_the_publishing_job_may_write_contents() {
    let (_, workflow) = release();
    assert_eq!(workflow.permissions, scopes(&[]));
    let jobs: Vec<(&str, &Option<Permissions>)> = workflow
        .jobs
        .iter()
        .map(|j| (j.id.as_str(), &j.permissions))
        .collect();
    assert_eq!(
        jobs,
        [
            ("build", &scopes(&[("contents", "read")])),
            (
                "attest",
                &scopes(&[("attestations", "write"), ("id-token", "write")])
            ),
            ("publish", &scopes(&[("contents", "write")])),
        ]
    );
}

#[test]
fn every_action_is_pinned_and_no_checkout_keeps_the_token() {
    let (_, workflow) = release();
    assert_eq!(workflow.unpinned_uses(), Vec::<&str>::new());
    for job in &workflow.jobs {
        assert!(job.timeout_minutes.is_some(), "{}: no timeout", job.id);
        for step in &job.steps {
            if step
                .uses
                .as_deref()
                .is_some_and(|u| u.starts_with("actions/checkout@"))
            {
                assert_eq!(
                    step.with.get("persist-credentials").map(String::as_str),
                    Some("false"),
                    "{}",
                    job.id
                );
            }
        }
    }
}

#[test]
fn three_targets_build_natively_on_github_hosted_runners_and_are_attested() {
    let (text, workflow) = release();
    for (target, runner) in [
        ("x86_64-unknown-linux-gnu", "ubuntu-24.04"),
        ("aarch64-unknown-linux-gnu", "ubuntu-24.04-arm"),
        ("aarch64-apple-darwin", "macos-15"),
    ] {
        assert!(
            text.contains(&format!(
                "- target: {target}\n            runner: {runner}\n"
            )),
            "{target} on {runner}"
        );
    }
    let build = workflow.job("build").unwrap();
    assert!(build.steps.iter().any(|s| s.run.as_deref()
        == Some("cargo build --release --locked -p brakes --target \"$TARGET\"")));
    let attest = workflow.job("attest").unwrap();
    assert!(attest.steps.iter().any(|s| {
        s.uses
            .as_deref()
            .is_some_and(|u| u.starts_with("actions/attest-build-provenance@"))
            && s.with.get("subject-checksums").map(String::as_str) == Some("dist/SHA256SUMS")
    }));
    assert_eq!(workflow.job("publish").unwrap().needs, ["attest"]);
}
