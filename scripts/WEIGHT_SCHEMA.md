# Weight Schema — Canonical Reference

**Status:** `metadata.schemaVersion: 2`
**Adopted by:** `src/data/qwerty-model.json`, `src/data/shell_corpus.ndjson`,
`scripts/shell_markov_model.json`, `scripts/ssh_timing_stats.json`,
`scripts/ssh_proposed_qwerty_baselines.json`, `scripts/ssh_aligned_digraphs.json`,
and any future JSON / NDJSON data surface the SSH-keystroke decoder consumes.

---

## 1. Rationale

The decoder today treats every datum as equally trustworthy: a published
Gaussian prior for `same-key` digraphs is mixed with empirically observed
delays and a hand-tuned Markov transition probability with no notion of
*which number we trust more*. That works until we want to improve any one
of those sources — there's no place to record *how much* a given sample
should move the model.

The v2 weight schema fixes that. Every entry, transition, statistic, and
corpus record carries the same five-field envelope:

| Field         | Type           | Required? | Semantics                                                                  |
|---------------|----------------|-----------|----------------------------------------------------------------------------|
| `weight`      | number 0.0–1.0 | yes       | Confidence / quality of this datum. 1.0 = treat as ground truth.          |
| `count`       | number \| null | yes       | Observation count. `null` if synthetic or otherwise non-countable.         |
| `source`      | string         | yes       | Provenance tag (see § 3).                                                  |
| `lastUpdated` | ISO date       | yes       | When this entry was last edited.                                           |
| `variance`    | number \| null | optional  | Uncertainty (e.g. observed std-dev for a Gaussian). `null` for point ests. |
| `tags`        | string[]       | optional  | Flex labels for filtering / grouping.                                      |

`weight` is the field the training pipeline will read. `count` is the
field that lets the trainer switch between *additive smoothing* and
*Bayesian shrinkage* (Bayesian mode is for when `count` is sparse and we
want a strong prior). `source` is what makes `count` useful — without
provenance, `count` is just a number.

---

## 2. Worked examples

### 2.1 Synthetic (a published Gaussian prior, no empirical data)

```json
{
  "name": "sameKey",
  "mean": 118,
  "std": 22,
  "weight": 1.0,
  "count": null,
  "source": "published",
  "lastUpdated": "2025-12-01",
  "variance": 484,
  "tags": ["digraph-baseline", "same-key"]
}
```

`weight: 1.0` because published priors are our baseline trust. `count: null`
because the prior isn't an observation — it's an analytical estimate.
`variance` is set to `std²` so downstream code can reconstruct either form.

### 2.2 Empirical (we recorded 1,247 keystrokes of this digraph)

```json
{
  "key": "th",
  "mean_ms": 162.3,
  "weight": 0.85,
  "count": 1247,
  "source": "empirical",
  "lastUpdated": "2026-01-14",
  "variance": 1240.7,
  "tags": ["digraph", "common", "english"]
}
```

`weight: 0.85` because empirical counts can be noisy (this is the default
the calibrator will produce in Step 1; tweak per-digraph later). `count:
1247` lets the trainer apply a Bayesian prior shrinkage toward the
published baseline when the empirical count is low.

### 2.3 Mixed provenance (a digraph profile with empirical + prior components)

```json
{
  "key": "qw",
  "mean_ms": 88.1,
  "weight": 0.72,
  "count": 412,
  "source": "empirical+published",
  "lastUpdated": "2026-01-15",
  "variance": 312.0,
  "tags": ["digraph", "cross-row", "left-handed-bias"]
}
```

The `source` string is a free-form provenance label; combiners are
allowed. The reader does not parse it — the trainer does.

### 2.4 Corpus record (NDJSON, one shell command per line)

```json
{"text": "ls -la", "weight": 0.95, "count": 145, "source": "manual", "lastUpdated": "2026-01-15", "tags": ["common", "directory-listing"]}
```

The corpus migrator (`scripts/migrate_weights.mjs`) writes these from
`src/data/shell_corpus_sorted.txt` (1211 plain-text lines → NDJSON, each
record wrapped with default weights from `~/.config/packetsnitch/
corpus-weights.json` if it exists).

---

## 3. Provenance tags

The `source` field is a free-form string, but the following values are
*reserved* and have specific meanings:

| Tag                      | Meaning                                                                                              |
|--------------------------|------------------------------------------------------------------------------------------------------|
| `published`              | Hardcoded prior from a published study or textbook. Weight 1.0 by convention.                        |
| `empirical`              | Measured directly from a real PCAP / SSH capture. `count` is the number of observations.            |
| `manual`                 | Hand-tuned by a developer. Weight reflects confidence in the hand-tuning.                          |
| `calibrated`             | Output of `scripts/calibrate_ssh.py`. Weight reflects goodness-of-fit on the training set.         |
| `synthesized`            | Generated by a script (e.g. `merge_empirical.py` concatenating two sources). `count` is null.       |
| `empirical+published`    | Bayesian blend of the two. `count` is the effective observation count post-shrinkage.                |
| `tldr` / `cheatsheet`    | Drawn from a public shell-command reference. Generally `count: null`, `weight: 0.6–0.8`.            |
| `user-override`          | User has hand-edited this entry (via the Settings → Decoder tab). Weight 1.0; overrides everything.  |

Don't invent new tags without updating this table — the trainer reads
these labels when it decides how aggressively to update each entry.

---

## 4. Migration policy

**One-time auto-migrator**, bundled in the repo:

| File                                  | Role                                                |
|---------------------------------------|-----------------------------------------------------|
| `scripts/migrate_weights.mjs`         | Migrates `src/data/qwerty-model.json` to v2.        |
| `scripts/migrate_weights.py`          | Migrates Python-output JSON (`scripts/*.json`).     |
| `scripts/migrate_corpus_to_ndjson.mjs`| Migrates `src/data/shell_corpus_sorted.txt` → NDJSON. |

Each migrator:

1. Reads the source file.
2. Walks every leaf that fits the v1 shape and wraps it with the v2
   envelope.
3. Writes `<basename>.v2.json` (or `<basename>.ndjson`) alongside the
   original — **never overwrites**.
4. The new reader transparently prefers `.v2` / `.ndjson` if present,
   falls back to v1 with all weights defaulted to `1.0`.

`v1` files remain readable forever — the wrappers are *additive*. A v1
reader will simply ignore the `weight` / `count` / `source` fields it
doesn't understand. **No backwards-incompatible write.**

---

## 5. Versioning rule

Every JSON file carries:

```json
{
  "metadata": {
    "schemaVersion": 2,
    "lastMigratedAt": "2026-01-15T00:00:00Z"
  }
}
```

`schemaVersion: 1` files remain readable; readers log a one-time warning
on first read and continue. `schemaVersion: 2` is the new minimum for
new writes.

Every corpus file (NDJSON) carries a `corpus_format` header line as its
first record:

```json
{"corpus_format": "ndjson", "schemaVersion": 2, "fields": ["text", "weight", "count", "source", "lastUpdated", "tags"]}
```

Plain-text corpus files (legacy) are detected by the absence of this
header and read line-by-line, treating each line as `{"text": <line>}`.

---

## 6. How the decoder reads weights (today vs future)

| Layer                     | Today (v1)              | Tomorrow (v2)                                                   |
|---------------------------|-------------------------|-----------------------------------------------------------------|
| Digraph Gaussian          | Picks published prior   | Picks `max(weight)` source; shrinks empirical toward prior      |
| Markov transition         | Uses raw probability    | Multiplies by `weight`; respects `count` for smoothing          |
| Capture-context prior     | Hardcoded heuristic     | Weights by `count` of in-capture artifacts (temporal proximity) |
| Beam search reranker      | None                    | Adds `sum(weight * log p)` term to the score                    |

None of the v2 behaviors are required for v2 to ship — the schema is a
*carrying mechanism*, not a behavior change. The decoder continues to
work when weights are uniformly `1.0`. That property is what makes
the migration safe.

---

## 7. Where to add weights in each file (quick map)

| File                                                       | What gets wrapped                                                          |
|------------------------------------------------------------|----------------------------------------------------------------------------|
| `src/data/qwerty-model.json` → `baselines[*]`              | each baseline entry (`sameKey`, `adjacentKey`, etc.)                       |
| `src/data/qwerty-model.json` → `commonDigraphs` / `samples`| merge into `entries` map, keyed by digraph string                           |
| `src/data/qwerty-model.json` → new `digraphs`              | every digraph Gaussian record                                              |
| `src/data/shell_corpus.ndjson`                             | every line record (`text` + envelope)                                      |
| `scripts/shell_markov_model.json` → `transitions[*]`       | every transition entry                                                     |
| `scripts/ssh_timing_stats.json` → `stats[*]`               | every statistic block                                                      |
| `scripts/ssh_proposed_qwerty_baselines.json`               | every proposed baseline entry                                              |
| `scripts/ssh_aligned_digraphs.json` → `records[*]`         | every aligned digraph record                                               |

---

## 8. Don't

- **Don't** put `weight` on a *non-leaf* (e.g. don't weight a whole
  baseline group — weight the individual entries). Weights compose by
  multiplication, so nested weights are ambiguous.
- **Don't** use `weight: 0` to mean "ignore" — use `count: 0` or remove
  the entry. Zero weight is a strong claim; treat it like `NaN`.
- **Don't** add fields to the envelope without updating § 1. The trainer
  schema is fixed; extensibility goes in `tags`.
- **Don't** parse `source` as an enum. It's a string. Tags are free-form.
- **Don't** make weights conditional on runtime state (time of day,
  user, session). Keep the file deterministic; put conditional logic in
  the reader, not the data.

---

## 9. See also

- `memories/session/plan.md` — the parent 13-step plan
- `scripts/migrate_weights.mjs` — JSON migrator (Step 0b)
- `scripts/migrate_corpus_to_ndjson.mjs` — corpus migrator (Step 0c)
- `src/ui/decoders/ssh-keystrokes/markov.js` — consumer (`ShellMarkov.fromDict`)
- `scripts/calibrate_ssh.py` — calibrator that will *write* weights (Step 1)
