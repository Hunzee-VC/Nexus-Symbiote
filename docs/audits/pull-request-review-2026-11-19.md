# Pull-request, branch and label review — 2026-11-19

Baseline: `main` at `f6045e2` (after #271). Continues the
[2026-11-03 review](closed-pr-review-2026-11-03.md), which covered #74–#116, and the
[2026-11-02 review](closed-pr-review-2026-11-02.md), which covered #2–#73. The
[machine-readable record](pull-request-review-2026-11-19.json) lists every pull request from #117 to
#291, every merge measured below and every branch with its class.

## Scope and method

- **Merged pull requests #117–#274.**
  - **Direct landings.** 50 commits on `main`'s first-parent history since #117 each landed one
    pull request and carry its number: 36 squash commits through #233, then 14 merge commits from
    #236 on, with the integrations #202, #203, #226 and #227. Each was compared with current
    `main`. The measure is how many of its added lines are still in the same file. Only lines of at
    least eight characters count, compared with surrounding whitespace stripped and without rename
    detection, and `CHANGELOG.md`, lock files, JSON and `docs/audits/` are left
    out.
  - **Hand review.** A merge that kept less than four-fifths of its lines was reviewed by hand.
    `git log -S` names the later commit that removed each sampled line, and every test the merge
    added was looked up on `main` by name.
  - **Merges through another pull request.** 67 pull requests reached `main` through an integration
    pull request or the joint merge commit `9e068cb` (#146, #147). The measure of the integration
    covers them; `9e068cb` itself was not measured.
- **Closed without merging.** The page of each pull request closed without merging was read for a
  stated reason, and its labels for its disposition.
- **Open pull requests.** For each pull request open at the baseline, the description, labels and
  latest review were read against ROADMAP.md as proposed in #267 (`9655e5a`).
- **Branches.** Every branch and every `refs/pull/*/head` was fetched. As in the 2026-11-03 review,
  a branch is *preserved* when each of its commits is reachable from `main` or from a pull-request
  ref, which GitHub keeps after a branch is deleted.

These records show what reached `main`. They do not re-certify historical heads.

## Findings

| Finding | Evidence | Disposition |
| --- | --- | --- |
| No merged change was silently reverted | The 50 direct landings added about 139,000 such lines, and 4.4% of them (6,166) are no longer on `main`. Seven merges kept less than four-fifths of their lines. In each case a later, named change explains the loss, and none dropped a regression test; see [merges reviewed by hand](#merges-reviewed-by-hand) | None needed |
| Component pull requests of an integration branch read "closed", not "merged" | GitHub marks a pull request merged only when its head reaches its own base branch. #209–#214, #216 and #217 targeted `integration/2026-11-14-batch-3`; #215 targeted #211's branch and #219 targeted #218's batch-4 branch. All ten reached `main` through #226 (`87be091`) | Each has a closing comment naming #226, and each is now labelled `superseded`; see [process notes](#process-notes) |
| Fourteen pull requests had no labels | #109, #112, #113, #115, #117, #125, #222, #226, #227 and #250 were merged; #104 and #114 were closed without merging; #289 and #291 were open | Type and area labels added. #104 and #114 also carry `superseded` |
| Five closed pull requests gave no reason on their own page | #20, #22, #59, #60 and #61. Their dispositions were recorded only in the 2026-11-02 review | Each now has a comment that states its disposition and cites that review |
| Open pull requests claim the same roadmap rows | Fourteen rows had two or three open implementations at the baseline; see [overlapping claims](#overlapping-claims) | Needs the owner's decision for each row. Each open description now starts with a "Maintainer context" block that names its overlaps |
| Open pull requests cross recorded decisions | #272 (tool shadowing), #285 (an MCP proxy), #286 (a completeness score, a retirement catalog without a source, results that depend on the wall clock), #284 and #288 (discovery that the 18 November scope decision gives to ShadowScan), #281 (Cedar and Rego export), #289 (a verdict of passed when nothing was read) and #291 (a file walk outside the selected collectors) | Needs the owner's decision; listed on #200 |
| Two descriptions list work their diff does not contain | #268 lists parser fuzzing, `make precision`, the staged policy checker, CODEOWNERS and export element bounds. #275 lists CODEOWNERS | Flagged in each description's "Maintainer context" block; the authors' text is unchanged |
| `severity:` labels carry two meanings | On fixes they rate the vulnerability fixed. On feature pull requests, reviewers use them for the most severe open review finding | Both meanings are written down in the [label guide](../labels.md) |
| 241 of 349 branches can be deleted without losing a commit | Recomputed on 2026-11-19 at 16:30 UTC: 110 are merged into `main` and 131 are preserved by pull-request refs; 35 back open pull requests | Listed for the owner to delete; see [branches](#branches) |
| Issue #220 does not exist | The API returns 404 for #220, so it was most likely deleted | Recorded |

### Repository settings and records

The owner checks or changes these in the repository settings. The repository settings API was read
for this review on 2026-11-19. The tag list, the Actions workflow list and the v0.1.0 release were
read through the GitHub API.

| Finding | Evidence | Action |
| --- | --- | --- |
| Secret scanning and push protection are off | The settings API reports `secret_scanning` and `secret_scanning_push_protection` as `disabled`, while [repository controls](../repository-controls.md) recorded them as enabled, with no date. No CI job scans for secrets either; Gitleaks is not a required job | This change corrects the record. The owner enables both, then dates the row |
| 0.2.0 is recorded as released but was not published | `CHANGELOG.md` has `## [0.2.0] - 2026-11-12` and `CITATION.cff` has `date-released: "2026-11-12"`. The only tag is `v0.1.0`, and 162 entries (65 marked **Breaking**) sit under Unreleased, above 0.2.0 | Decide at publication (`R0.2.0-1` in #267): either fold Unreleased into 0.2.0 dated on the day it is published, or number the release 0.3.0 |
| Two workflows are registered on GitHub but are not on `main` | Actions lists "Platform smoke" at `.github/workflows/platform-smoke.yml`, registered 2026-11-03 beside `platforms.yml` of the same name; its file is on no branch and it last ran on 2026-11-03. It also lists "Offline invariant verification" (`offline-invariant.yml`), registered 2026-11-19 from #287's branch | Disable `platform-smoke.yml`. `offline-invariant.yml` follows #287 |
| The v0.1.0 release has no distributions attached | Its assets are three Sigstore bundles, `release-evidence.tar.gz` and `SHA256SUMS`. The wheel and the sdist are on PyPI only, the environment SBOM is inside the tarball, and the release is not marked immutable | Attach both distributions after checking them against `SHA256SUMS`. Attach `environment.cdx.json` in future releases |
| Merged branches stay | The settings API reports `delete_branch_on_merge` as false. 241 branches can be deleted without losing a commit; see [branches](#branches) | Turn on automatic deletion of head branches, and delete the listed branches |
| All three merge methods are allowed | Merge, squash and rebase are enabled. `main` has used merge commits since #236, and a squash merge silently reverted #99 (2026-11-03 review) | Allow merge commits only |
| Eight labels have no description | `audit-2026-11`, `breaking-change`, `code quality`, `needs-independent-review`, `refactor`, `severity: high`, `severity: medium` and `severity: low` | Copy each label's one-line meaning from the [label guide](../labels.md). Five more (`bug`, `enhancement`, `wontfix`, `duplicate`, `security`) keep GitHub's defaults, which differ from the guide |
| The repository description is out of date | It reads "Supports and Extends Cyclone 1.7 DX and SPDX 3.0", with trailing spaces. Exports are CycloneDX 1.7 and SPDX 3.0.1 | Rewrite it |
| The changelog declares no format and rarely names pull requests | No format line, no compare links, and 2 of its 361 entries cite a pull request (2 more cite issue #74). Three entries are over 5,000 characters | Declare Keep a Changelog, end each new entry with `(#N)`, and keep entries to a few sentences. Restructure when 0.2.0 is published |

### Merges reviewed by hand

| Merge | Kept | Why lines are missing | Tests it added |
| --- | --- | --- | --- |
| #117 `ba2b5b6` | 23% of 64 | README and docs rewritten by #125, #126, #130 and #145 | None |
| #119 `56ea0a5` | 52% of 31 | Release docs reworded by #124, #125 and #130 | None |
| #125 `9a607ab` | 24% of 67 | Its known-limitations statements in README, `SECURITY.md` and the controls and security-model docs were rewritten mainly by #130, then #129 and #126 | None |
| #129 `59f1fc8` | 79% of 834 | Collectors reworked mainly by the v0.1.0 audit remediation #130, and later by #226 and #128 | 38; 36 by name, and #149 renamed the other two (`test_long_failure_lists_are_summarized`, `test_reasons_are_neutralized_for_the_terminal` in `tests/test_gate_reasons.py`) |
| #142 `4c5d8a5` | 79% of 265 | Docs and tests reworked by #145, #149, #202 and #203 | 8; 7 by name, and #145 renamed the README check to `test_protect_the_gate_avoids_pull_request_target_head_checkout` in `tests/test_audit_pr4_release_ci_docs.py`, which now reads `docs/drift-gate.md` |
| #228 `0ce0170` | 56% of 710 | #231 redesigned the opted-out launcher's wrapper the same day. `PR_SET_CHILD_SUBREAPER` and the `CLONE_PARENT` sweep remain in `live/pinned_process.py` | 14; 13 by name, and #231 replaced the other with `test_a_launcher_cannot_end_its_wrapper_with_a_signal` |
| #233 `b1cc2f1` | 4 of 6 | #271 raised the coverage job's limits again; #233's test-matrix and floor limits remain | None |

## Pull requests #117–#291

| Pull request | Disposition |
| --- | --- |
| #117–#145, #149, #150, #157, #227 (re-applies #154), #228, #230, #231, #233, #245, #249, #252, #271, #274 | Merged directly. Their changes are on `main` or were deliberately reworked by a later pull request; see [merges reviewed by hand](#merges-reviewed-by-hand) |
| #146, #147 | Merged together as `9e068cb` ("Merge #147 (with #146)") |
| #202 | Merged: batch 1 of the 2026-11-14 audit. It carries #148, #155, #158, #159, #162, #163, #165, #166, #169, #177, #178, #186, #196 and #198 |
| #203 | Merged: batch 2. It carries #151, #153, #156, #161, #164, #167, #168, #172, #173, #182, #187, #188, #191, #193 and #197 |
| #226 | Merged: the backlog, with batches 3 and 4 (#208, #218) and the review fixes. It carries #152, #171, #174–#176, #179–#181, #183–#185, #189, #190, #192, #194, #195, #204–#207, #221–#223 and #225. #154's commits are in its history, so GitHub shows #154 merged, but #226 reverted it (`dd87257`); #154 landed through #227 |
| #236 | Merged. It carries #232; #234 and #235 are listed below |
| #246, #247 | Merged: audit 2026-11-16 batches A and B1. They carry #237, #238, #240 and #244 and an earlier head of #239, then #241 and #243. #239's final head followed in #250 |
| #250, #251 | Merged: batches B2a and B2b. They carry #239 and #242 at their final heads |
| #160 | Closed. Superseded by #198, which landed in #202 |
| #170 | Closed. Superseded by #177, which refuses every weakening project-policy setting in CI and landed in #202 |
| #209–#217, #219 | Closed by hand. They landed on `main` through #226 (`87be091`) |
| #224 | Closed. Superseded by #228, which re-lands it without a cgroup |
| #229 | Closed. It landed on `main` through #230 (`ec38323`) |
| #234 | Closed by hand. Its content merged through #236 (`fef1983`) at head `a44edca` |
| #235 | Closed as a duplicate of #233, which set the same limits. Its head (`f131e8a`), which adds only a comment, later merged through #236 |
| #248 | Closed. Superseded by #250, which carries #239's final head |
| #199, #200, #201 | Issues. #200 is the merge coordination ledger and is still open |
| #220 | Not found; see the findings |
| #253–#270, #272, #273, #275–#291 | Open at the baseline; see [open pull requests](#open-pull-requests) |
| #259, #261 | Closed without merging later on 2026-11-19: #259 as superseded by #255 (labelled `superseded`), #261 on the maintainer's decision (labelled `wontfix`); `R1.1-2` and `R1.1-3` continue in #291 and #288 |

## Open pull requests

Rows are those of ROADMAP.md as proposed in #267. Review states are the labels on 2026-11-19 at
16:30 UTC, when #259 and #261 had closed. Each
description starts with a "Maintainer context" block that gives the latest review, the merge order
and the decisions that apply.

| Pull request | Rows | Review state | Note |
| --- | --- | --- | --- |
| #253 | none | `review: verified` | Audit follow-up to #242 |
| #254 | `R0.2.0-2` | `review: verified` |  |
| #255 | `R0.2.0-7` | `review: changes-needed` |  |
| #256 | `R0.2.0-3` | `review: changes-needed` |  |
| #257 | `R0.2.0-6` | `review: verified` |  |
| #258 | `R1.0.0-rc.1-2` | `review: verified` |  |
| #260 | `R0.2.0-4` | `review: changes-needed` |  |
| #262 | `R0.2.0-4` | `review: verified` | Part (c); #260 has (a) and (b) |
| #263 | `R0.2.0-5` | `review: verified` |  |
| #264 | `R1.1-4` | `review: verified` | Fix |
| #265 | `R0.3.0-3`, `R1.0.0-1` | `review: verified` | Fix |
| #266 | `R0.2.0-8` | `review: verified` |  |
| #267 | `Rshipped-7` | `review: verified` | The roadmap itself and AIBOM-Bench |
| #268 | `R1.1-6`, `R0.3.0-3`, `R1.0.0-rc.1-1`, `R0.3.0-1`, `Rshipped-4` | `review: verified` | Description lists work now in #275 or absent |
| #269 | `R1.0.0-rc.1-2` | `review: changes-needed` | Stacked on #258 |
| #270 | `R1.0.0-rc.1-5`, `R1.0.0-rc.1-4`, `R1.3-1` | `review: verified` | Part 1; #281 is part 2 |
| #272 | `R1.1-1` | `review: changes-needed` | Tool shadowing crosses a decision |
| #273 | `R1.2-1`, `R1.2-4` | `review: changes-needed` |  |
| #275 | `R0.3.0-1`, `R1.0.0-1`, `R1.0.0-2` | `review: changes-needed` | Description lists CODEOWNERS, not in its diff |
| #276 | `R1.1-10` | `review: changes-needed` |  |
| #277 | `R0.3.0-2` | `review: changes-needed` |  |
| #278 | none | `review: verified` | Fix to the graph view |
| #279 | `R1.0.0-rc.1-3`, `R1.3-4` | `review: changes-needed` |  |
| #280 | `R1.2-2`, `R1.1-8` | `review: changes-needed` |  |
| #281 | `R1.4-1`, `R1.3-3`, `R1.4-4` | `review: changes-needed` | Cedar and Rego export crosses a decision |
| #282 | none | `review: verified` | Package metadata |
| #283 | none | `review: verified` | Fix; stacked on #278 |
| #284 | `R1.1-4`, `R1.3-5`, `R1.3-6`, `R1.4-2` | `review: changes-needed` | Native discovery crosses the scope decision |
| #285 | `R1.3-2`, `R1.4-1` | `review: changes-needed` | MCP proxy crosses a non-goal |
| #286 | `R1.3-5` | `review: changes-needed` | Completeness score (draft item 31, delivered as Rshipped-6 coverage), retirement catalog and wall clock cross decisions |
| #287 | `R1.0.0-rc.1-1`, `R1.0.0-1`, `R1.0.0-2`, `R1.0.0-3` | `review: changes-needed` |  |
| #288 | `R1.1-3`, `R1.1-7`, `R1.2-3`, `R1.3-3`, `R1.4-3` | `review: changes-needed` | Native workflow reading crosses the scope decision |
| #289 | `R1.1-9`, `R1.3-2`, `R1.3-7`, `R1.4-1`, `R1.4-4`, `Rshipped-4` | `review: changes-needed` |  |
| #290 | none | `review: verified` | CI time limits; follows #271 |
| #291 | `R1.1-2` | `review: changes-needed` |  |

## Overlapping claims

These rows were claimed by two or more open pull requests at the baseline, not counting planned splits:
#255 with #259, #260 with #262 and #258 with #269. #278 and #283 are a stacked pair with no roadmap
row. After #259 and #261 closed, the `R1.1-2` and `R1.1-3` rows no longer overlap. The owner picks one implementation per row
or asks the authors to merge them.

| Row | Open pull requests |
| --- | --- |
| `R1.4-1` | #281, #285, #289 |
| `R0.3.0-1` | #268, #275 |
| `R0.3.0-3` | #265, #268 |
| `R1.0.0-1` | #265, #275, #287 |
| `R1.0.0-rc.1-1` | #268, #287 |
| `R1.0.0-2` | #275, #287 |
| `R1.3-2` | #285, #289 |
| `R1.4-4` | #281, #289 |
| `R1.3-3` | #281, #288 |
| `R1.3-5` | #284, #286 |
| `R1.1-4` | #264, #284 |
| `R1.1-2` | #261, #291 |
| `R1.1-3` | #261, #288 |
| `Rshipped-4` | #268, #289 |

## Branches

Counted on 2026-11-19 at 16:30 UTC, after #259 and #261 closed.

| Class | Branches | What to do |
| --- | --- | --- |
| Head of an open pull request | 35 | Keep |
| Merged into `main` | 110 | Delete; nothing is lost |
| Preserved by pull-request refs | 131 | Delete; every commit stays reachable through `refs/pull/N/head` |
| Holds commits on no other ref | 73 | Ask the owning session first. These include working branches that are still in use |

The [machine-readable record](pull-request-review-2026-11-19.json) names every branch in each class.

## Process notes

- **Integration branches.** Before folding component pull requests into an integration branch, target
  them at `main`, so that GitHub records them as merged when the integration lands. Otherwise close
  each one by hand with the integration's merge commit and label it `superseded`, as was done for
  batch 3.
- **Name the roadmap row and the decision.** Name the roadmap row a pull request implements and the
  recorded decisions it relies on. The pull-request template now asks for both, and the "Maintainer
  context" block records them for pull requests opened before that.
- **One open implementation per roadmap row.** Claim a row on #200 before you start, and check the
  open pull requests for the same row.
- **Descriptions match the diff.** When work moves between pull requests, update both descriptions.
