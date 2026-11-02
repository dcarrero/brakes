# Fleet audit example-org

Audited at 2026-10-28 over a 28-day window against the accepted standard, read as example-owner. Exit code 3.

| Repository | Profile | Required | Reached | Gap | Posture failures | CI minutes (sample) | Deployment frequency | Lead time | Open incidents | Post-merge corrections | Cost per change | Unavailable | Waiting |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| example-org/docs-site | P1 unverified | Bronze | none | 6 | 1 | failed | unavailable | unavailable | waiting | unavailable | unavailable | 25 | 13 |
| example-org/example-app | P1 unverified | Bronze | none | 4 | 4 | 120.5 min | passed | 0.2 h | waiting | unavailable | unavailable | 8 | 13 |

## example-org/docs-site

Exit code 3; 35 of 100 calls.

```text
AUDIT example-org/docs-site: profile P1 unverified (humans unavailable, cadence unavailable, services unavailable, criticality undeclared); required Bronze; reached none
COUNTER post-merge-corrections: unavailable: pull requests of example-org/docs-site was not found (404: Not Found)
COUNTER cost-per-change: unavailable: pull requests of example-org/docs-site was not found (404: Not Found)
FAIL        [basic:baseline.purpose-declared] .agent-setup/project.json missing → manual step declare-purpose: Write one sentence in `purpose` of .agent-setup/project.json.
FAIL        [basic:baseline.verify-declared] .agent-setup/project.json missing → manual step declare-verify: Declare the project's own command in `commands.verify` of .agent-setup/project.json.
FAIL        [basic:baseline.criticality-declared] .agent-setup/project.json missing → manual step declare-criticality: Set `criticality` in .agent-setup/project.json to internal, customers or personal-data-or-payments.
UNAVAILABLE [basic:posture.default-branch-protected] protection of branch main in example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [basic:posture.no-open-secret-scanning-alerts] open secret-scanning alerts of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [bronze:posture.required-check-enforced] protection of branch main in example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [bronze:posture.no-unlisted-bypass-actors] protection of branch main in example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [bronze:posture.no-stale-critical-alerts] open Dependabot alerts of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [bronze:posture.no-repo-secrets-with-production] environments of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [silver:posture.production-environment-guarded] environments of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [bronze:posture.stale-branches] branches of example-org/docs-site was not found (404: Not Found)
FAIL        [gold:posture.org-2fa-required] organization example-org does not require two-factor authentication → manual step require-2fa: Enable Require two-factor authentication under the organization's Authentication security settings.
FAIL        [basic:ci-health.workflow-exists] no workflow under .github/workflows → module ci-baseline
UNAVAILABLE [silver:ci-health.cancellation-rate] workflow runs of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [silver:dora.deployments-api-in-use] production deployments of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [gold:dora.time-to-restore] issues of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [silver:dora.deployment-frequency] production deployments of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [silver:dora.lead-time] production deployments of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [silver:dora.change-failure-rate] production deployments of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [silver:operations.post-deploy-smoke] waits for module delivery
UNAVAILABLE [silver:operations.rollback-evidence] waits for module delivery
UNAVAILABLE [silver:operations.uptime-footprint] waits for module observability
UNAVAILABLE [silver:operations.incidents-bounded] waits for module incidents
UNAVAILABLE [silver:operations.runbook-per-alert] waits for module incidents
UNAVAILABLE [gold:operations.slo-burn-rate-validated] waits for module incidents
UNAVAILABLE [gold:operations.backup-age-within-rpo] waits for module continuity
UNAVAILABLE [gold:operations.restore-drill-fresh] waits for module continuity
FAIL        [bronze:governance.dependency-updates-with-cooldown] neither .github/dependabot.yml nor renovate.json configures dependency updates → module repo-baseline
FAIL        [bronze:governance.service-card-owner] no service card: .agent-setup/service.yaml, service.yaml or catalog-info.yaml → module repo-baseline
FAIL        [bronze:governance.pr-template-and-issue-forms] no pull request template in .github/, the root or docs/; no issue form (.yml) under .github/ISSUE_TEMPLATE → module repo-baseline
UNAVAILABLE [gold:governance.postmortem-actions-closed] issues of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [gold:governance.no-expired-flags] waits for module flags
UNAVAILABLE [gold:governance.cost-tags] waits for module iac
UNAVAILABLE [silver:ci.required-is-aggregate] protection of branch main in example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [silver:ci.main-red] no workflow under .github/workflows declares a job named required
UNAVAILABLE [gold:ci.minutes-month] workflow runs of example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [bronze:security.secret-scanning] repository example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [bronze:security.private-vulnerability-reporting] repository example-org/docs-site was not found (404: Not Found)
UNAVAILABLE [gold:security.attestation-verified] waits for module delivery
UNAVAILABLE [gold:security.sbom-scanned] waits for module delivery
NEXT Basic: 6 rules (baseline.criticality-declared, baseline.purpose-declared, baseline.verify-declared, ci-health.workflow-exists, posture.default-branch-protected, posture.no-open-secret-scanning-alerts)
```

## example-org/example-app

Exit code 3; 70 of 100 calls.

```text
AUDIT example-org/example-app: profile P1 unverified (humans unavailable, cadence unavailable, services single, criticality undeclared); required Bronze; reached none
COUNTER post-merge-corrections: unavailable: pull requests of example-org/example-app was not found (404: Not Found)
COUNTER cost-per-change: unavailable: pull requests of example-org/example-app was not found (404: Not Found)
FAIL        [basic:baseline.purpose-declared] purpose is empty in .agent-setup/project.json → manual step declare-purpose: Write one sentence in `purpose` of .agent-setup/project.json.
FAIL        [basic:baseline.verify-declared] commands.verify is not declared in .agent-setup/project.json → manual step declare-verify: Declare the project's own command in `commands.verify` of .agent-setup/project.json.
FAIL        [basic:baseline.criticality-declared] criticality undeclared in .agent-setup/project.json (audited as internal) → manual step declare-criticality: Set `criticality` in .agent-setup/project.json to internal, customers or personal-data-or-payments.
UNAVAILABLE [basic:posture.no-open-secret-scanning-alerts] open secret-scanning alerts of example-org/example-app was not found (404: error)
FAIL        [bronze:posture.required-check-enforced] main requires checks all-checks-passed; the aggregate check required is not among them → module repo-baseline
FAIL        [bronze:posture.actions-pinned] Unpinned action actions/checkout@v4 in .github/workflows/ci.yml; Unpinned action actions/checkout@v4 in .github/workflows/ci.yml; Unpinned action actions/checkout@v4 in .github/workflows/ci.yml → manual step pin-actions: Replace each tag or branch after @ with the full commit SHA it points to, keeping the tag as a comment.
UNAVAILABLE [bronze:posture.no-stale-critical-alerts] Reading open Dependabot alerts of example-org/example-app is forbidden (403: error)
FAIL        [bronze:posture.no-repo-secrets-with-production] repository-level secrets with a production environment: ANTHROPIC_API_KEY, ASC_PRIVATE_KEY, AUTOPILOT_GH_TOKEN, DEEPINFRA_API_KEY, SENTRY_API_TOKEN, SENTRY_WRITE_TOKEN → manual step move-secrets-to-environments: Move each repository-level secret into the environment that uses it, then delete it at repository level.
FAIL        [gold:posture.org-2fa-required] organization example-org does not require two-factor authentication → manual step require-2fa: Enable Require two-factor authentication under the organization's Authentication security settings.
UNAVAILABLE [silver:operations.post-deploy-smoke] waits for module delivery
UNAVAILABLE [silver:operations.rollback-evidence] waits for module delivery
UNAVAILABLE [silver:operations.uptime-footprint] waits for module observability
UNAVAILABLE [silver:operations.incidents-bounded] waits for module incidents
UNAVAILABLE [silver:operations.runbook-per-alert] waits for module incidents
UNAVAILABLE [gold:operations.slo-burn-rate-validated] waits for module incidents
UNAVAILABLE [gold:operations.backup-age-within-rpo] waits for module continuity
UNAVAILABLE [gold:operations.restore-drill-fresh] waits for module continuity
FAIL        [bronze:governance.dependency-updates-with-cooldown] neither .github/dependabot.yml nor renovate.json configures dependency updates → module repo-baseline
FAIL        [bronze:governance.service-card-owner] no service card: .agent-setup/service.yaml, service.yaml or catalog-info.yaml → module repo-baseline
FAIL        [bronze:governance.pr-template-and-issue-forms] no pull request template in .github/, the root or docs/; no issue form (.yml) under .github/ISSUE_TEMPLATE → module repo-baseline
UNAVAILABLE [gold:governance.postmortem-actions-closed] issues of example-org/example-app was not found (404: Not Found)
UNAVAILABLE [gold:governance.no-expired-flags] waits for module flags
UNAVAILABLE [gold:governance.cost-tags] waits for module iac
FAIL        [silver:ci.required-is-aggregate] Required checks are all-checks-passed; expected only required → module ci-baseline
UNAVAILABLE [silver:ci.main-red] no workflow under .github/workflows declares a job named required
UNAVAILABLE [gold:ci.minutes-month] workflow runs of example-org/example-app was not found (404: Not Found)
UNAVAILABLE [bronze:security.secret-scanning] repository example-org/example-app has an unexpected shape: missing number field id
UNAVAILABLE [bronze:security.private-vulnerability-reporting] repository example-org/example-app has an unexpected shape: missing number field id
UNAVAILABLE [gold:security.attestation-verified] waits for module delivery
UNAVAILABLE [gold:security.sbom-scanned] waits for module delivery
NEXT Basic: 4 rules (baseline.criticality-declared, baseline.purpose-declared, baseline.verify-declared, posture.no-open-secret-scanning-alerts)
```

## Not audited

- example-org/old-prototype: archived (pass --include-archived to audit it)
