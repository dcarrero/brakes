//! The coverage-upload recipe per pack (#20, part of #19): what the project's own
//! CI test job runs so `diff-coverage` judges data it never measures itself. A
//! pack with a coverage tool renders the install, the measured run and the
//! upload of `agentic-coverage-<app id>-<job>`; a pack without one says why and
//! renders nothing, never a fallback that runs the tests in a job of `brakes`.
use brakes::modules::{
    security::diff_coverage,
    stack_packs::{App, PinTable, StackId, coverage_artifact, packs, steps_yaml},
};
use std::{collections::BTreeMap, fs, path::PathBuf};

/// The shell a test job hands the recipe: the declared command, read at run time.
const TEST: &str = "bash -euo pipefail -c \"$TEST_COMMAND\"";
const GOLDENS: &str = "../../templates/stack-packs/goldens";

fn pins() -> PinTable {
    PinTable::embedded().unwrap()
}

fn app(stack: StackId, path: &str) -> App {
    App {
        id: if path == "." {
            "root".to_owned()
        } else {
            path.rsplit('/').next().unwrap().to_owned()
        },
        path: path.to_owned(),
        stack,
        container: false,
        toolchain: true,
        package_manager: None,
        declared: BTreeMap::new(),
    }
}

fn golden(name: &str, text: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(GOLDENS)
        .join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_GOLDENS=1", path.display()));
    assert!(text == expected, "{name} differs from the golden:\n{text}");
}

/// What the golden of `stack` holds: the steps of a root app's `test` job, or the reason.
fn rendered(stack: StackId) -> String {
    let pack = packs::pack(stack);
    match (pack.coverage, pack.no_coverage) {
        (Some(recipe), None) => {
            let steps = recipe
                .upload_steps(&app(stack, "."), "test", TEST, &pins(), None)
                .unwrap();
            format!(
                "# {}: the test job's coverage steps (#20)\n{}",
                stack.as_str(),
                steps_yaml(&steps)
            )
        }
        (None, Some(reason)) => format!("# {}: no coverage upload: {reason}\n", stack.as_str()),
        _ => panic!("{stack}: exactly one of coverage and no_coverage"),
    }
}

#[test]
fn every_pack_declares_its_upload_or_says_why_it_has_none() {
    for stack in StackId::ALL {
        let pack = packs::pack(stack);
        match (pack.coverage, pack.no_coverage) {
            (Some(_), None) => {}
            (None, Some(reason)) => assert!(
                reason.len() > 20 && !reason.contains("brakes runs"),
                "{stack}: {reason}"
            ),
            _ => panic!("{stack}: exactly one of coverage and no_coverage"),
        }
    }
}

#[test]
fn each_pack_matches_its_golden() {
    for stack in StackId::ALL {
        golden(
            &format!("coverage-upload-{}.yml", stack.as_str()),
            &rendered(stack),
        );
    }
}

#[test]
fn the_rust_upload_measures_the_declared_command_unchanged() {
    let recipe = packs::pack(StackId::Rust).coverage.unwrap();
    let steps = recipe
        .upload_steps(&app(StackId::Rust, "."), "test", TEST, &pins(), None)
        .unwrap();
    let run = steps
        .iter()
        .find_map(|s| s.run.clone())
        .expect("a measured run");
    // cargo-llvm-cov README at v0.9.1, "Get coverage of external tests".
    assert_eq!(
        run,
        format!(
            "eval \"$(cargo llvm-cov show-env --sh)\"\ncargo llvm-cov clean --workspace\n{TEST}\ncargo llvm-cov report --lcov --output-path lcov.info"
        )
    );
    let upload = steps.last().unwrap();
    assert_eq!(
        upload.uses.as_ref().unwrap().repo,
        "actions/upload-artifact"
    );
    assert_eq!(upload.with["name"], "agentic-coverage-root-test");
    assert_eq!(upload.with["path"], "lcov.info");
    assert_eq!(upload.with["if-no-files-found"], "error");
    assert!(!upload.with.contains_key("include-hidden-files"));
}

#[test]
fn the_python_upload_runs_pytest_under_coverage_and_keeps_the_hidden_data_file() {
    let recipe = packs::pack(StackId::PythonUv).coverage.unwrap();
    let steps = recipe
        .upload_steps(
            &app(StackId::PythonUv, "."),
            "test",
            TEST,
            &pins(),
            Some("-m \"not services\""),
        )
        .unwrap();
    let run = steps.iter().find_map(|s| s.run.clone()).unwrap();
    // coverage.py measures only the interpreter it starts: the measured run takes
    // the place of the declared command, and says so in the step name.
    assert!(!run.contains(TEST), "{run}");
    assert_eq!(
        run,
        "COVERAGE_CORE=sysmon uv run --frozen --all-extras --with coverage==7.17.0 --with pytest-cov==7.1.0 python -m pytest -q --cov --cov-report= -m \"not services\""
    );
    let upload = steps.last().unwrap();
    assert_eq!(upload.with["path"], ".coverage");
    assert_eq!(upload.with["include-hidden-files"], "true");
}

#[test]
fn an_app_in_a_directory_measures_and_uploads_from_it() {
    let recipe = packs::pack(StackId::Rust).coverage.unwrap();
    let api = app(StackId::Rust, "services/api");
    let steps = recipe
        .upload_steps(&api, "test", TEST, &pins(), None)
        .unwrap();
    let run = steps.iter().find(|s| s.run.is_some()).unwrap();
    assert_eq!(run.working_directory.as_deref(), Some("services/api"));
    let upload = steps.last().unwrap();
    assert_eq!(upload.with["name"], "agentic-coverage-api-test");
    assert_eq!(upload.with["path"], "services/api/lcov.info");
}

#[test]
fn the_artifact_is_the_one_diff_coverage_downloads() {
    for stack in [StackId::Rust, StackId::PythonUv] {
        let a = app(stack, "web");
        assert_eq!(
            coverage_artifact(&a, "test"),
            format!("{}test", diff_coverage::artifact_prefix(&a))
        );
    }
}

#[test]
fn a_job_name_that_is_not_kebab_case_refuses() {
    let recipe = packs::pack(StackId::Rust).coverage.unwrap();
    let error = recipe
        .upload_steps(&app(StackId::Rust, "."), "Test Job", TEST, &pins(), None)
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "stack-packs: the coverage artifact's job `Test Job` must be kebab-case"
    );
}
