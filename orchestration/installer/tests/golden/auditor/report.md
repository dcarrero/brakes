# Audit example-owner/example

Audited at 2026-10-28 over a 28-day window against the accepted standard.

| Repository | Profile | Required | Reached | Gap | Unavailable | Waiting |
|---|---|---|---|---|---|---|
| example-owner/example | P1 | Bronze | none | 4 | 21 | 13 |

## example-owner/example

```text
AUDIT example-owner/example: profile P1 (1 human, cadence low, services single, criticality undeclared); required Bronze; reached none
COUNTER post-merge-corrections: unavailable: no pull request merged 2026-08-31..2026-09-28 to judge
COUNTER cost-per-change: unavailable: workflow runs of example-owner/example was not found (404: Not Found: repos/example-owner/example/actions/runs?per_page=100&page=1)
FAIL        [basic:baseline.criticality-declared] criticality undeclared in .agent-setup/project.json (audited as internal) → manual step declare-criticality: Set `criticality` in .agent-setup/project.json to internal, customers or personal-data-or-payments.
UNAVAILABLE [basic:posture.default-branch-protected] protection of branch main in example-owner/example was not found (404: Not Found: repos/example-owner/example/branches/main/protection)
UNAVAILABLE [basic:posture.no-open-secret-scanning-alerts] open secret-scanning alerts of example-owner/example was not found (404: Not Found: repos/example-owner/example/secret-scanning/alerts?state=open&hide_secret=true&per_page=100&page=1)
UNAVAILABLE [bronze:posture.required-check-enforced] protection of branch main in example-owner/example was not found (404: Not Found: repos/example-owner/example/branches/main/protection)
UNAVAILABLE [bronze:posture.no-unlisted-bypass-actors] protection of branch main in example-owner/example was not found (404: Not Found: repos/example-owner/example/branches/main/protection)
UNAVAILABLE [bronze:posture.no-stale-critical-alerts] open Dependabot alerts of example-owner/example was not found (404: Not Found: repos/example-owner/example/dependabot/alerts?state=open&per_page=100)
UNAVAILABLE [bronze:posture.no-repo-secrets-with-production] repository secret names of example-owner/example was not found (404: Not Found: repos/example-owner/example/actions/secrets?per_page=100&page=1)
UNAVAILABLE [bronze:posture.stale-branches] branches of example-owner/example was not found (404: Not Found: repos/example-owner/example/branches?per_page=100&page=1)
UNAVAILABLE [gold:posture.org-2fa-required] owner example-owner was not found (404: Not Found: users/example-owner)
FAIL        [basic:ci-health.workflow-exists] no workflow under .github/workflows → module ci-baseline
UNAVAILABLE [silver:ci-health.cancellation-rate] workflow runs of example-owner/example was not found (404: Not Found: repos/example-owner/example/actions/runs?per_page=100&page=1)
UNAVAILABLE [silver:dora.deployments-api-in-use] production deployments of example-owner/example was not found (404: Not Found: repos/example-owner/example/deployments?environment=production&per_page=100&page=1)
UNAVAILABLE [gold:dora.time-to-restore] issues of example-owner/example was not found (404: Not Found: repos/example-owner/example/issues?state=closed&labels=incident&since=2026-09-30T00%3A00%3A00Z&per_page=100&page=1)
UNAVAILABLE [silver:dora.deployment-frequency] production deployments of example-owner/example was not found (404: Not Found: repos/example-owner/example/deployments?environment=production&per_page=100&page=1)
UNAVAILABLE [silver:dora.lead-time] production deployments of example-owner/example was not found (404: Not Found: repos/example-owner/example/deployments?environment=production&per_page=100&page=1)
UNAVAILABLE [silver:dora.change-failure-rate] production deployments of example-owner/example was not found (404: Not Found: repos/example-owner/example/deployments?environment=production&per_page=100&page=1)
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
UNAVAILABLE [gold:governance.postmortem-actions-closed] issues of example-owner/example was not found (404: Not Found: repos/example-owner/example/issues?state=open&labels=type%3Apost-mortem-action&per_page=100&page=1)
UNAVAILABLE [gold:governance.no-expired-flags] waits for module flags
UNAVAILABLE [gold:governance.cost-tags] waits for module iac
UNAVAILABLE [silver:ci.required-is-aggregate] protection of branch main in example-owner/example was not found (404: Not Found: repos/example-owner/example/branches/main/protection)
UNAVAILABLE [silver:ci.main-red] no workflow under .github/workflows declares a job named required
UNAVAILABLE [gold:ci.minutes-month] workflow runs of example-owner/example was not found (404: Not Found: repos/example-owner/example/actions/runs?status=completed&created=%3E%3D2026-09-28&per_page=100&page=1)
UNAVAILABLE [gold:security.attestation-verified] waits for module delivery
UNAVAILABLE [gold:security.sbom-scanned] waits for module delivery
NEXT Basic: 4 rules (baseline.criticality-declared, ci-health.workflow-exists, posture.default-branch-protected, posture.no-open-secret-scanning-alerts)
```
