//! `node`: a `package.json` with one lockfile, which names the package manager.
//! CI sets pnpm up first when it is the manager, sets Node up with its own
//! cache off (it cannot restrict saving), and uses the explicit restore/save
//! pair on the manager's store. setup-node's `cache` names a package manager;
//! `package-manager-cache: false` is the input that turns caching off (#1166).
use crate::{Result, refuse};
use std::fmt;

use super::{
    super::{
        App, ContainerSupport, Evidence, Healthcheck, Lockfile, OtelKind, OtelRecipe,
        PackageManager, PinTable, ProposedCommands, Runtime, SeedFile, StackId, StackPack, Step,
        TestRunnerProfile, setup_core_guide,
    },
    OTEL_ENV, cache_key, cache_pair, run_in,
};

pub const LOCKFILES: [&str; 4] = [
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
];

pub const NODE: StackPack = StackPack {
    id: StackId::Node,
    evidence: &[
        Evidence::AllOf(&["package.json"]),
        Evidence::AnyOf(&LOCKFILES),
    ],
    proposed: ProposedCommands {
        build: Some("{{pm}} run build"),
        test: Some("{{pm}} test"),
        lint: Some("{{pm}} run lint"),
        verify: Some("{{lint}} && {{test}}"),
    },
    // npm's pair; `PackageManager::lockfile` and `install` carry the others.
    lockfile: Some(Lockfile {
        file: "package-lock.json",
        strict_flag: "ci",
    }),
    toolchain_seed: Some(SeedFile {
        path: ".nvmrc",
        template: include_str!("../../../../../../templates/stack-packs/node/nvmrc"),
    }),
    container: ContainerSupport::Capable {
        runtime: Runtime::Node,
        port_default: 3000,
        healthcheck_default: Healthcheck::Command(
            r#"["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:{{port}}/').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]"#,
        ),
    },
    dependabot_ecosystem: "npm",
    // The default npm registry, also the one pnpm and bun read.
    egress_hosts: &["registry.npmjs.org"],
    macos_target: false,
    // By runner: `NodeRunner::profile` once detection or `qa` names it.
    test_runner: None,
    otel: Some(OtelRecipe {
        kind: OtelKind::ZeroCode,
        packages: &[
            "@opentelemetry/api",
            "@opentelemetry/auto-instrumentations-node",
        ],
        entrypoint_hint: r#"["/nodejs/bin/node", "--require", "@opentelemetry/auto-instrumentations-node/register", "index.js"]"#,
        env: OTEL_ENV,
        guide: setup_core_guide("docs/agent-setup/observability.md#node"),
    }),
    coverage: None,
    no_coverage: Some(
        "no line-coverage tool is pinned for node: the runners differ (jest, vitest, node:test) and none is chosen, so diff-coverage does not judge node apps until the pack declares one",
    ),
    properties: None,
    mutation: None,
    ci_setup,
};

/// The node test runners detection recognises (SPEC-stack-packs.md, Open
/// question 3, closed in #767): by `devDependencies` name, `node:test` by
/// `node --test` in `scripts.test`; `qa` asks when none is found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeRunner {
    Vitest,
    Jest,
    NodeTest,
    Playwright,
}

impl NodeRunner {
    /// In precedence order: unit runners before Playwright, which is end to
    /// end and is the runner only when it is the one found.
    pub const ALL: [NodeRunner; 4] = [
        NodeRunner::Vitest,
        NodeRunner::Jest,
        NodeRunner::NodeTest,
        NodeRunner::Playwright,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeRunner::Vitest => "vitest",
            NodeRunner::Jest => "jest",
            NodeRunner::NodeTest => "node:test",
            NodeRunner::Playwright => "playwright",
        }
    }
    /// The `devDependencies` name that reveals the runner; `node:test` is
    /// built into Node and has none.
    pub const fn dev_dependency(self) -> Option<&'static str> {
        match self {
            NodeRunner::Vitest => Some("vitest"),
            NodeRunner::Jest => Some("jest"),
            NodeRunner::NodeTest => None,
            NodeRunner::Playwright => Some("@playwright/test"),
        }
    }
    /// `{{exec}}` is `PackageManager::exec`. Sharding stays `None` as for the
    /// other packs: `qa` proposes it, nothing here installs or enables it.
    pub const fn profile(self) -> TestRunnerProfile {
        match self {
            NodeRunner::Vitest => TestRunnerProfile {
                one_test: "{{exec}} vitest run -t '{{name}}'",
                shard: None,
                junit: Some("--reporter=junit --outputFile={{out}}"),
                list_tests: Some("{{exec}} vitest list"),
            },
            // jest writes JUnit only through the `jest-junit` reporter package.
            NodeRunner::Jest => TestRunnerProfile {
                one_test: "{{exec}} jest -t '{{name}}'",
                shard: None,
                junit: None,
                list_tests: Some("{{exec}} jest --listTests"),
            },
            NodeRunner::NodeTest => TestRunnerProfile {
                one_test: "node --test --test-name-pattern='{{name}}'",
                shard: None,
                junit: Some("--test-reporter=junit --test-reporter-destination={{out}}"),
                list_tests: None,
            },
            NodeRunner::Playwright => TestRunnerProfile {
                one_test: "{{exec}} playwright test -g '{{name}}'",
                shard: None,
                junit: None,
                list_tests: Some("{{exec}} playwright test --list"),
            },
        }
    }
}

impl fmt::Display for NodeRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PackageManager {
    pub const ALL: [PackageManager; 4] = [
        PackageManager::Npm,
        PackageManager::Pnpm,
        PackageManager::Yarn,
        PackageManager::Bun,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Yarn => "yarn",
            PackageManager::Bun => "bun",
        }
    }
    pub const fn lockfile(self) -> &'static str {
        match self {
            PackageManager::Npm => "package-lock.json",
            PackageManager::Pnpm => "pnpm-lock.yaml",
            PackageManager::Yarn => "yarn.lock",
            PackageManager::Bun => "bun.lock",
        }
    }
    /// The lockfile-strict install.
    pub const fn install(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm ci",
            PackageManager::Pnpm => "pnpm install --frozen-lockfile",
            PackageManager::Yarn => "yarn install --immutable",
            PackageManager::Bun => "bun install --frozen-lockfile",
        }
    }
    /// What runs a binary the project installed, `{{exec}}` of a test-runner
    /// profile.
    pub const fn exec(self) -> &'static str {
        match self {
            PackageManager::Npm => "npx",
            PackageManager::Pnpm => "pnpm exec",
            PackageManager::Yarn => "yarn",
            PackageManager::Bun => "bunx",
        }
    }
    /// The download store CI caches (not `node_modules`).
    pub const fn store(self) -> &'static str {
        match self {
            PackageManager::Npm => "~/.npm",
            PackageManager::Pnpm => "~/.local/share/pnpm/store",
            PackageManager::Yarn => "~/.cache/yarn",
            PackageManager::Bun => "~/.bun/install/cache",
        }
    }
    /// The manager named by the lockfiles among `present` (other names are
    /// ignored); none is `None`, two refuse naming both.
    pub fn from_lockfiles(present: &[&str]) -> Result<Option<PackageManager>> {
        let found: Vec<PackageManager> = PackageManager::ALL
            .into_iter()
            .filter(|pm| present.contains(&pm.lockfile()))
            .collect();
        match found.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            [first, second, ..] => refuse(format!(
                "stack-packs: both {} and {} are present; keep the lockfile of one package manager",
                first.lockfile(),
                second.lockfile()
            )),
        }
    }
}

impl fmt::Display for PackageManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn ci_setup(app: &App, pins: &PinTable) -> Result<Vec<Step>> {
    let Some(pm) = app.package_manager else {
        return refuse(format!(
            "stack-packs: app `{}` is node but names no package manager; one of {} must be present at `{}`",
            app.id,
            LOCKFILES.join(", "),
            app.path
        ));
    };
    let mut steps = Vec::new();
    if pm == PackageManager::Pnpm {
        steps.push(
            Step::new("Install pnpm")
                .uses(pins.action("pnpm/action-setup")?)
                .with("run_install", "false"),
        );
    }
    let mut node = Step::new("Set up Node")
        .uses(pins.action("actions/setup-node")?)
        .with("package-manager-cache", "false");
    node = if app.toolchain {
        node.with("node-version-file", format!("{}.nvmrc", app.prefix()))
    } else {
        node.with("node-version", pins.tool("node")?.version.clone())
    };
    let (restore, save) = cache_pair(
        pins,
        &format!("{pm} store"),
        pm.store(),
        &cache_key(pm.as_str(), app, pm.lockfile()),
    )?;
    steps.extend([
        node,
        restore,
        run_in(app, "Install dependencies", pm.install()),
        save,
    ]);
    Ok(steps)
}
