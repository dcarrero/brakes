Summary (one line):

<!-- brakes:begin -->
- [ ] Verification output is in this PR (the command and its result, not "CI green")
- [ ] Migration is backwards-compatible (expand/contract) or there is no migration
- [ ] Every flag this PR touches was tested in both states
- [ ] The flag is removed, or its removal issue is linked with a date (a story does not close with a live flag)
- [ ] The slice is ≤ 400 changed lines, or the PR says why it cannot be split
<!-- brakes:end -->

Notes for review: only what the diff does not say (why, risk, rollback).
