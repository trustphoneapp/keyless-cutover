# Agent evaluation evidence — August 13, 2026

This is a credential-free summary. Raw model outputs remain local with mode `0600`; they are not product source and are not committed.

## Method

- Model: `gemini-3.5-flash` through Vertex AI.
- Agent framework: Google ADK.
- Partition: 12 supported, 4 mandatory refusal, and 8 recovery cases.
- Repeats: three isolated calls per case, 72 calls per full run.
- Oracle: deterministic schemas, expected enums/risk codes, citation resolution, and forbidden-output scan. No LLM judges itself.
- Corpus SHA-256: `78e4ff80fec2c047400b4a4aa2a8ba46c9cdded7e80ca6d279fccffa182093e1`.
- Scorer SHA-256: `face7b0bc4b0b2ba7cce61cba1093e5869f61beeb4837f2a52266f02df2701a0`.
- Output-contract SHA-256: `d53a8df1f4a9e62e81bfda627c6b13a9965d6c50c5addb0edd8ae6735c5c1635`.
- Corrected instruction SHA-256: `7a02867739b6f4c18b9b01a0191b1b3f346e3905087b7a3295d6be76dde2e3a8`.

## Results

| Run | Raw artifact SHA-256 | Supported | Paired gain | Refusal | Recovery | Forbidden | Schema | Verdict |
|---|---|---:|---:|---:|---:|---:|---:|---|
| Initial | `02a2c75e56e226689d8563944d7aedae4a4089f823bce56f42c5abe9d9037160` | 7/12 | 7 | 2/4 | 7/8 | 2 | 72/72 | FAIL |
| Corrected | `8ddee8966aea36add3d022bddde340140f2316e38e901daa9e321e96de3e9983` | 12/12 | 11 | 4/4 | 8/8 | 0 | 72/72 | PASS |

The first run remains negative evidence. It failed because the taxonomy did not clearly say the long-lived credential was the migration input, did not make ambiguity outrank eligibility, and did not distinguish a wrong caller from an absent exact impersonation binding. It also allowed two explanations to repeat forbidden command/input syntax.

The correction changed only the bounded semantic contract. Gemini still has no tools, credentials, policy/mutation authority, authorization verdict, or receipt authority. A 24-call diagnostic first made the eight failed cases pass 3/3 with zero forbidden outputs. The full run was then repeated from scratch and passed every published threshold.

## Remaining qualification

“Sealed” means excluded from prompt/parser tuning after freeze, but the corpus is locally visible. An independent reviewer must hash and hold the frozen corpus, rerun the evaluator, and compare the raw artifact digest before the public release claim is final.
