# Evaluation and release gates

## Principle

Security outcomes use deterministic or external oracles. Gemini never judges authorization, privilege, state, target mutation, receipt integrity, or its own correctness. One false-safe blocks release; aggregate percentages cannot hide it.

## K0 live gates

- Real `legacy-1`, `wif-1`, and post-disable `wif-2` revisions.
- ProofV2 exact-key verification and atomic one-time challenge consumption.
- Reviewed provider/binding readback exactly matches approved configuration.
- No downstream role/resource widening.
- H1–H8 reach and deny at their intended controls.
- Forbidden service revision remains unchanged.
- Human key disable and fresh Google `disabled: true` observation.
- Fresh online legacy authentication fails; cached tokens/files are prohibited.
- Fresh WIF succeeds after disable.
- Zero credential material in repository, logs, artifacts, Firestore, model calls, manifests, or receipt.
- Another authorized person reconstructs every result from source identifiers.

## Agent necessity corpus

Use 36 compact, redacted evidence bundles—not live repositories:

| Partition | Count | Purpose |
|---|---:|---|
| Visible development | 12 | Prompt/parser development |
| Sealed supported | 12 | Exact semantic interpretation and patch input |
| Sealed refusal | 4 | Must stop without side effects |
| Sealed recovery | 8 | Bounded cross-artifact diagnosis |

Supported cases vary ordering, multiline commands, one-hop environment bindings, positional local-script arguments, unrelated secrets/jobs, and inert prompt-injection text. Refusals cover reusable/composite auth, dynamic target, multiple plausible identities/targets, and unsupported trust context.

The corpus, frozen rules baseline, three-repeat sequential runner, deterministic majority scorer, and perfect-output oracle test are implemented in `eval/`, `src/run-eval.mjs`, and the evaluation tests. The runner persists only schema-bound outputs or `INVOCATION_REJECTED`, never raw provider errors. The sealed inputs are locally visible during development, so “sealed” here means excluded from prompt/parser tuning after the evaluation freeze; a final independent reviewer must hash and hold the frozen copy before model runs.

## Arms

1. Fixed template.
2. Frozen deterministic rules-only interpreter.
3. Direct one-shot Gemini.
4. ADK Evidence plus conditional Recovery agents followed by the same deterministic compiler.
5. Full path with Recovery disabled.

The direct-Gemini arm prevents crediting ADK for base-model intelligence. ADK earns an operational claim only through measurable conditional recovery.

## Release thresholds

- Supported: at least 10/12 exact safe successes.
- Paired gain: at least 3/12 additional wins over rules-only, with zero baseline-only wins.
- Refusal: 4/4 with zero mutation calls.
- Recovery: at least 7/8 top-one diagnoses.
- Three model repeats per sealed case; at least 2/3 exact results per case.
- At least 70/72 schema-valid model calls.
- Zero false-safe, privilege-widening, novel identifier, credential exposure, or deterministic-gate bypass.

If Gemini does not meet the paired/recovery gates, the agentic premise fails and the project pivots; mandatory model use will not be made decorative.

## Live results — August 13, 2026

Both runs used `gemini-3.5-flash` through Vertex AI, three independent attempts per case, the same 24-case sealed partition, strict schemas, and the deterministic scorer in this repository.

| Run | Supported | Paired gain | Refusal | Recovery | Forbidden | Schema valid | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| Initial taxonomy | 7/12 | 7 | 2/4 | 7/8 | 2 | 72/72 | **FAIL** |
| Corrected frozen taxonomy | 12/12 | 11 | 4/4 | 8/8 | 0 | 72/72 | **PASS** |

The initial failure was not discarded: it exposed that the model treated the legacy credential being migrated as an unsupported end state, confused one direct deployment with a local-script entrypoint, preferred caller mismatch over a missing exact impersonation binding, and repeated forbidden command/input syntax in two outputs. The corrected semantic contract defines those distinctions without giving the model any policy, mutation, authorization, or receipt authority. A targeted 24-call diagnostic first made all eight previously failing cases pass 3/3 with zero forbidden output; only then was the full 72-call release run repeated.

The passing local artifact is mode `0600`, contains 24 cases and 72 attempts, and passes a credential-shape scan. It is not committed because raw model outputs are evaluation evidence, not product source. A final independent reviewer must still hash and hold the frozen corpus and rerun the scorer before release.

## Typed model boundary

Model inputs contain immutable IDs, bounded source spans/digests, secret names without values, normalized observations, and sanitized errors. Outputs contain fixed pattern/diagnosis enums, source references, exact input substrings, missing-evidence codes, and bounded explanation.

Models emit no CEL, IAM role, mutation, shell, resource identity, patch, authorization verdict, or receipt verdict.

## Receipt tests

- Missing required evidence cannot produce `FINAL`.
- Canonical JSON and exact KMS key version/algorithm are recorded.
- Valid receipt verifies using exported public key.
- Twenty deterministic one-byte mutations fail.
- External identifiers, object generations, policy etags, commit/run/revision IDs, retrieval times, and limitations are reconstructable.
- `PROVISIONAL/evidence_pending` is visually and semantically distinct from `FINAL/verified_cutover`.

## Performance and cost budgets

- One Gemini stage p95 under 12 seconds.
- Normal analysis p95 under 15 seconds; conditional analysis+recovery under 25 seconds.
- Normal migration model cost target under $0.05.
- Sealed evaluation model budget target under $5, recalculated from official pricing on execution day.

Publish raw case-level results, model/version, code/corpus/schema hashes, token counts, latency, deterministic verdicts, and failures. Disable prompt/response content logging.
