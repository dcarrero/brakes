//! The files `qa` writes (`SPEC-qa.md`, Seeds; Project Structure): the `.hurl`
//! seeds under `<qa_dir>/api/` when `api`, the Playwright project under
//! `web_dir` when `web == seeded`, both written once and the project's
//! afterwards; the managed guide; and the `never-touch` listing of what is
//! already the project's (its root Playwright configuration, its test
//! directories and every `.hurl` file the module did not seed).
use super::{PLAYWRIGHT_CONFIGS, QaAnswers, TEST_DIRS, Web, hurl};
use crate::{
    Result,
    engine::{Ownership, Rendered},
    modules::stack_packs::{PinTable, seeds::fill},
};
use std::{collections::BTreeSet, path::Path};

pub const GUIDE_PATH: &str = "docs/agent-setup/qa.md";
/// The `.hurl` seeds, relative to `<qa_dir>`.
pub const READY_HURL: &str = "api/00-ready.hurl";
pub const SMOKE_HURL: &str = "api/smoke.hurl";
/// The Playwright seeds, relative to `web_dir`.
pub const WEB_SEEDS: [&str; 3] = ["package.json", "playwright.config.ts", "smoke.spec.ts"];
/// The baseline Playwright writes for the seeded test, relative to `web_dir`:
/// `<test file>-snapshots/<arg>-<project>-<platform>.png`, fixed by the seed's
/// `toHaveScreenshot('home.png')`, its `chromium` project and the Linux runner.
pub const BASELINE: &str = "smoke.spec.ts-snapshots/home-chromium-linux.png";

const GUIDE: &str = include_str!("../../../../../templates/qa/qa.md");
const READY_SEED: &str = include_str!("../../../../../templates/qa/seeds/api/00-ready.hurl");
const SMOKE_SEED: &str = include_str!("../../../../../templates/qa/seeds/api/smoke.hurl");
const PACKAGE_SEED: &str = include_str!("../../../../../templates/qa/seeds/web/package.json");
const CONFIG_SEED: &str =
    include_str!("../../../../../templates/qa/seeds/web/playwright.config.ts");
const SPEC_SEED: &str = include_str!("../../../../../templates/qa/seeds/web/smoke.spec.ts");

/// Directories never walked for `.hurl` files.
const SKIP_DIRS: [&str; 4] = ["node_modules", "target", "vendor", ".git"];
/// How deep the walk for `.hurl` files goes.
const HURL_DEPTH: usize = 8;

/// `a/b`, where `.` is the directory itself and each `..` of `b` removes one
/// segment of `a`: an app's `web_dir` may climb out of the app (#1211), which
/// `QaAnswers::load` keeps inside the repository.
pub fn join(a: &str, b: &str) -> String {
    let mut parts: Vec<&str> = a.split('/').filter(|s| !matches!(*s, "" | ".")).collect();
    for segment in b.split('/') {
        match segment {
            "." => {}
            ".." => {
                parts.pop();
            }
            segment => parts.push(segment),
        }
    }
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
}

fn file(path: String, class: Ownership, content: Option<String>) -> Rendered {
    Rendered {
        path,
        class,
        content,
        scaffold: None,
    }
}

/// The managed guide, its `{{tools.playwright}}` and `{{images.playwright}}`
/// filled from the shared pin table.
pub fn guide(pins: &PinTable) -> Result<Rendered> {
    let text = fill(&crate::setup_core_text(GUIDE)?, pins)?
        .replace("{{images.playwright}}", &pins.image("playwright")?.pinned());
    Ok(file(GUIDE_PATH.to_owned(), Ownership::Managed, Some(text)))
}

/// The seeds of every target, the root first and then each listed app, with
/// paths relative to the repository root. A `.hurl` seed whose request line
/// names a host refuses.
pub fn seeds(answers: &QaAnswers, pins: &PinTable) -> Result<Vec<Rendered>> {
    let root = Target {
        path: ".",
        api: answers.api,
        ready: &answers.api_ready_path,
        web: answers.web,
        web_dir: &answers.web_dir,
    };
    let apps = answers.apps.values().map(|app| Target {
        path: &app.path,
        api: app.api,
        ready: &app.api_ready_path,
        web: app.web,
        web_dir: &app.web_dir,
    });
    let mut out = Vec::new();
    for target in std::iter::once(root).chain(apps) {
        if target.api {
            let base = join(target.path, &answers.qa_dir);
            // Both request the one path the installer knows the API serves (#1216).
            let ready = READY_SEED.replace("{{api_ready_path}}", target.ready);
            let smoke = SMOKE_SEED.replace("{{api_ready_path}}", target.ready);
            for (name, text) in [(READY_HURL, ready), (SMOKE_HURL, smoke)] {
                let path = join(&base, name);
                hurl::check_seed(&path, &text)?;
                out.push(file(path, Ownership::Seed, Some(text)));
            }
        }
        if target.web == Web::Seeded {
            let base = join(target.path, target.web_dir);
            let package = fill(PACKAGE_SEED, pins)?;
            for (name, text) in
                WEB_SEEDS
                    .into_iter()
                    .zip([package, CONFIG_SEED.to_owned(), SPEC_SEED.to_owned()])
            {
                out.push(file(join(&base, name), Ownership::Seed, Some(text)));
            }
        }
    }
    Ok(out)
}

struct Target<'a> {
    path: &'a str,
    api: bool,
    ready: &'a str,
    web: Web,
    web_dir: &'a str,
}

/// What is already the project's, declared `never-touch` so no module ever
/// renders it: at the root and at each listed app, an existing
/// `playwright.config.*` and `<dir>/**` for each existing test directory;
/// every `.hurl` file in the repository that is not one of `rendered`; and the
/// contracts and their ruleset.
pub fn never_touch(root: &Path, answers: &QaAnswers, rendered: &[Rendered]) -> Vec<Rendered> {
    let ours: BTreeSet<&str> = rendered.iter().map(|r| r.path.as_str()).collect();
    let mut paths = BTreeSet::new();
    let targets = std::iter::once(".").chain(answers.apps.values().map(|a| a.path.as_str()));
    for target in targets {
        for config in PLAYWRIGHT_CONFIGS {
            let path = join(target, config);
            if root.join(&path).is_file() {
                paths.insert(path);
            }
        }
        for dir in TEST_DIRS {
            let path = join(target, dir);
            if root.join(&path).is_dir() {
                paths.insert(format!("{path}/**"));
            }
        }
    }
    hurl_files(root, root, HURL_DEPTH, &mut paths);
    // The contracts `qa-contracts` judges and their ruleset are the project's (#1016).
    let targets = std::iter::once((".", &answers.contracts)).chain(
        answers
            .apps
            .values()
            .map(|a| (a.path.as_str(), &a.contracts)),
    );
    for (base, contracts) in targets {
        for path in contracts.files() {
            paths.insert(join(base, path));
        }
    }
    paths
        .into_iter()
        .filter(|path| !ours.contains(path.as_str()))
        .map(|path| file(path, Ownership::NeverTouch, None))
        .collect()
}

/// Every `*.hurl` file under `dir`, relative to `root`; hidden directories,
/// `SKIP_DIRS` and symlinks are not followed.
fn hurl_files(root: &Path, dir: &Path, depth: usize, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if depth > 0 && !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_str()) {
                hurl_files(root, &path, depth - 1, out);
            }
        } else if kind.is_file()
            && name.ends_with(".hurl")
            && let Ok(relative) = path.strip_prefix(root)
        {
            out.insert(relative.to_string_lossy().into_owned());
        }
    }
}
