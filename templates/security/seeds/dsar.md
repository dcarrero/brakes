# Runbook — data subject access and erasure requests (DSAR)

Last verified: 2026-10-29

Seeded by brakes (security) from `.agent-setup/pii.yaml`; this file is the
project's from now on. A DSAR is an interruption with a legal clock: this runbook is
the decision tree for answering one, not a description of the data model. The
declaration is the owner's statement of the fields that hold personal data; keep both
in step in the same pull request.

## When it fires

- Alert or symptom that triggers this runbook: a data subject asks for access,
  rectification, portability or erasure, through `{{dsar_contact}}` or any other route.
- Expected false-positive rate and how to confirm quickly: verify the requester's
  identity before any data leaves; a request for someone else's data is refused.
- Severity bucket once confirmed: the clock is `{{sla_days}}` days from receipt
  (controller: `{{controller}}`).

## Safety notes

- Commands that are safe to run read-only: lookups by the identifier fields below.
- Commands that mutate state and the approval needed: every erasure or anonymisation
  is run once, by one named operator, after the identity check, and recorded below.
- Side effects of common diagnostic steps: a lookup must not write to logs, traces,
  analytics or CDC streams that the declaration excludes the field from.
- Conditions that require escalating before acting: a `retain-legal` field, a
  request naming a third party, or a subject under a dispute or legal hold.

## Diagnosis steps

1. Confirm the request type (access, rectification, portability, erasure) and the
   date received; start the `{{sla_days}}`-day clock.
2. Confirm identity; record how.
3. Locate the subject in every storage listed below by the identifier fields.
4. Distinguish erasure from anonymisation and from legal retention per field.

## Classification

Fields by erasure action, from `.agent-setup/pii.yaml`:

### Delete

| Field | Storage | Category | Retention |
|---|---|---|---|
{{delete_rows}}

### Anonymise

| Field | Storage | Category | Retention |
|---|---|---|---|
{{anonymise_rows}}

### Retain under a legal obligation (named in the field's purpose)

| Field | Storage | Category | Retention |
|---|---|---|---|
{{retain_rows}}

## Actions

For each storage above, list the exact command or UI step, its expected output and
how long to wait before deciding it failed.

1. Access or portability: export the subject's rows from every storage; redact the
   fields of other subjects; deliver through the agreed channel.
2. Erasure: delete the `delete` fields, anonymise the `anonymise` fields, leave the
   `retain-legal` fields and tell the subject which obligation keeps them.
3. Propagate: backups, replicas, analytics and CDC targets that the declaration does
   not exclude; record each target.

## Post-action checks

- Service health signal that confirms recovery: the lookups of step 3 return nothing
  for the deleted fields.
- User-visible verification that can be run safely: the answer sent to the subject.
- Monitoring that should return to baseline: none expected.
- Things to watch for in the next N minutes: a re-import from a backup or an
  upstream feed that restores deleted rows.

## Record of what was done

- Time, action, result, operator:
- Any deviation from the runbook and why:

## Escalation

- When to escalate: the clock is within 5 days of expiry, a legal hold applies, a
  breach is suspected, or the subject disputes the answer.
- Who to contact and how: the controller `{{controller}}`; the project owner.
- What information to hand over: request type and date, identity check, storages
  searched, actions taken, the fields retained and their obligation.
