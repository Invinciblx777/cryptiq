# Cryptiq frontend/backend contract

## Status: backend side only

The frontend project could not be audited. The path given in the request was
still the literal placeholder `<PATH-TO-THE-IMPORTED-FRONTEND-PROJECT>`, and
neither `Cryptiq.dc.html` nor `support.js` exists anywhere under
`/home/v0idsai`. Searched: the whole home directory to depth 8 by name, and
every directory modified in the last day.

So this document records **one** of the two sides. The "Frontend expects",
"Conflicts" and parts of "Missing" sections are open until the frontend is
readable. Nothing here was inferred from what a frontend might plausibly want:
the shape below is derived from the backend's own model plus the observed /
inferred / derived separation the request specified, and it is a **proposal**
to be checked against the real frontend, not a verified agreement.

## Frontend expects

**Not yet determined.** Requires `Cryptiq.dc.html` and `support.js`.

Open questions that need the frontend to answer:

| Screen | What must be confirmed |
|---|---|
| Scan | Field names in the submit payload. Backend takes a repository URL and a 7-40 character commit SHA; whether the frontend sends `repo_url`/`repository_url`/`url` and `commit`/`commit_sha`/`ref` is unknown. |
| Scan status | Whether it polls, expects a job id, a scan id, or both; what status strings it renders. Backend has `ScanStatus` = QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED and a separate `ScanJobStatus`. |
| Results list | Which columns it renders, and whether it reads flat fields or the nested blocks proposed below. |
| Finding detail | Whether it expects `observed`/`inference`/`migration` nesting or a flat record. |
| Review queue | Sort and filter defaults; whether it keys on the review item id or the finding id. |
| Explain with AI | The request and response shape. No Gemini work was done, per the stop condition, but the field name and placement must come from the frontend. |

## Backend currently provides

The engine produces `AnalyzedFinding` (`app/engine/pipeline.py`):

```
AnalyzedFinding
  match       RuleMatch      rule_id, ruleset_version, algorithm, primitive,
                             library, api, operation, file_path, location,
                             confidence, evidence_basis, enclosing_function,
                             enclosing_class
  evidence    Evidence       repository_sha, file_path, start_line, end_line,
                             source_excerpt, rule_id, parser_version,
                             ruleset_version, truncated
  role        RoleAssessment role, rationale
  pqc         PqcAssessment  review_path, rationale, is_migration_candidate
  impact      ImpactResult   scope, confidence, nodes, relationships
  priority    PriorityResult level, score, reasons
  fingerprint str            sha256 hex, stable across commits
```

Database models exist for all nine domain entities, including `ReviewItem`
(status, assigned_to, note) and `Explanation` (provider, model, prompt_version,
status, summary, what_was_found, what_it_means, why_it_matters, review_action).
No findings are persisted yet: there is no write path from the engine to the
database.

## Missing

Known from the backend side, independent of the frontend:

* **Persistence.** Nothing writes a finding, evidence, impact node or review
  item. The API phase needs that before it can serve anything but a live scan.
* **Scan endpoints.** No route creates or reads a scan. `/health` is the only
  endpoint.
* **Worker loop.** Lifecycle rules and schema exist; nothing claims a job.
* **Explanation generation.** Deliberately absent.
* **Pagination and filtering.** `FindingPage` returns everything; a real scan
  produces 1441 findings on the acceptance commit, so the list endpoint will
  need paging, and the parameters should match whatever the frontend sends.

## Conflicts

**Not yet determinable** against the frontend. Two conflicts were found and
resolved *within* the backend while doing this work:

1. **Role vocabulary.** `app/db/models/enums.CryptographicRole` held a
   placeholder set (SIGNATURE, KEY_EXCHANGE, ENCRYPTION, KEY_DERIVATION,
   RANDOMNESS, CERTIFICATE) that the classifier does not produce. Resolved by
   migrating the column to the classifier's vocabulary
   (DIGITAL_SIGNATURE, KEY_ESTABLISHMENT, SYMMETRIC_ENCRYPTION, HASH,
   PROTOCOL, UNKNOWN). Migration `b87f2119dbab`. No rows existed.
2. **Enum constraints were never enforced in the database.** `enum_column`
   omitted `create_constraint`, which SQLAlchemy defaults to False, so every
   enum column was a bare VARCHAR and the values were checked only in Python.
   Fixed in the same migration; all thirteen enum columns now carry a named
   CHECK constraint.

## Resolution: the canonical finding

One field per fact, grouped by how much a reviewer can trust it.

```json
{
  "id": "<sha256 fingerprint, stable across commits>",
  "scan_id": "...",
  "repository": { "provider", "owner", "name", "url" },
  "commit_sha": "...",

  "observed": {
    "rule_id", "algorithm", "primitive", "library", "api", "operation",
    "location": { "file_path", "start_line", "end_line",
                  "start_column", "end_column" },
    "source_excerpt", "enclosing_function", "enclosing_class",
    "parser_version", "ruleset_version"
  },

  "inference": { "role", "rationale", "confidence", "evidence_basis" },

  "migration": { "review_path", "rationale",
                 "is_migration_candidate", "pqc_ruleset_version" },

  "impact":   { "scope", "node_count", "nodes": [...], "relationships": [...] },
  "priority": { "level", "score", "reasons": [...] },
  "review":   null | { "id", "status", "assigned_to", "note",
                       "created_at", "updated_at" }
}
```

### Why the grouping is part of the contract

`observed` is checkable: every field in it can be confirmed by opening the file
at that commit, and `source_excerpt` carries the text so the reviewer does not
have to. `inference` is what Cryptiq concluded — the role and how firmly the
rule established the match. `migration`, `impact` and `priority` follow from
the inference.

A flat record would let `role: "DIGITAL_SIGNATURE"` sit beside
`api: "RSAPrivateKey.sign"` as though both were facts about the file. They are
not: the second is in the source, the first is a judgement. A test asserts that
`role` and `confidence` never appear inside `observed`.

`migration.review_path` names guidance to read. It is never a replacement, and
a test asserts no rationale contains "replace with", "swap" or "automatically".
`is_migration_candidate` is true only for the two public-key paths, so a
symmetric or hash finding does not inflate the migration backlog.

### Vocabularies

| Field | Values |
|---|---|
| `observed.operation` | KEY_GENERATION, KEY_ESTABLISHMENT, SIGN, VERIFY, ENCRYPT, DECRYPT, CONSTRUCTION, HASH |
| `inference.role` | DIGITAL_SIGNATURE, KEY_ESTABLISHMENT, SYMMETRIC_ENCRYPTION, HASH, PROTOCOL, UNKNOWN |
| `inference.confidence` | HIGH, MEDIUM, LOW (UNKNOWN exists in the engine but is never emitted) |
| `inference.evidence_basis` | DIRECT_MODULE_API, CLASS_IMPORT, CLASS_ANNOTATION, CONSTRUCTOR_ASSIGNMENT, ESTABLISHED_ALIAS |
| `migration.review_path` | "ML-DSA / SLH-DSA", "ML-KEM", "KEY / IMPLEMENTATION REVIEW", "HASH / POLICY REVIEW", "MANUAL REVIEW" |
| `priority.level` | CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL (only HIGH/MEDIUM/LOW are produced) |
| `review.status` | OPEN, IN_REVIEW, REVIEWED |
| `impact.scope` | STATICALLY_OBSERVED (SCANNED_REPOSITORY is never produced) |

### Supporting shapes

`FindingSummary` is the list row: id, scan_id, algorithm, api, operation, role,
confidence, review_path, is_migration_candidate, priority, priority_score,
file_path, start_line, end_line, review_status. No excerpt, no impact graph.

`ReviewQueueItem` is the queue row: review_id, finding_id, scan_id, algorithm,
api, role, review_path, priority, priority_score, status, assigned_to, note,
file_path, start_line, updated_at. Ordered by priority score descending, then
by the engine's own order, so equal scores never swap between requests.

### Explicitly not in the contract yet

No `explanation` field. The frontend has an "Explain with AI" action, but its
shape is unknown and inventing one would mean the API promising something the
frontend does not ask for. It goes in once the frontend is readable.
