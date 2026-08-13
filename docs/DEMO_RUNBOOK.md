# Four-minute demonstration

## Truth contract

IAM/WIF propagation can take minutes and may exceed seven minutes. The video must not imply that provisioning, review, disable, and all tests finish synchronously.

Use one completed timestamped case plus one unedited live authorized/hostile pair. Every historical item is labeled `RECORDED/OBSERVED @ UTC`; current activity is labeled `LIVE`.

## Preconditions

- A completed reconstructable K0/K1 case exists.
- WIF/IAM is already propagated and read back.
- Exact key is already disabled and independently observed.
- H1–H8, `legacy-1`, `wif-1`, `wif-2`, and final receipt exist.
- Live PR triggers the authorized workflow and H4 wrong-workflow attempt in parallel.
- Five rehearsals show hostile denial within 45 seconds and authorized revision within 150 seconds.

## Timeline

### 0:00–0:25 — Hook and live launch

Launch the fresh authorized WIF deployment and H4 wrong-workflow attempt in one unedited action.

Say:

> “This deployment used a permanent Google key. Disable it blindly and releases break; leave it and one leak keeps working. Keyless proves the key, attacks the replacement, and only then asks a human to disable it—with a receipt.”

### 0:25–1:05 — Served agent action

Run Taskmaster on a supported workflow. Show Cloud Run, ADK, exact `gemini-3.5-flash` on Vertex AI, typed source citations, and a local-script interpretation or bounded recovery that the rules-only baseline missed.

### 1:05–1:35 — Deterministic boundary and draft PR

Show the no-added-downstream-privilege WIF diff and compiler-owned draft PR. Make the boundary explicit: Gemini interprets evidence; deterministic code owns policy and bytes; Keyless cannot merge or apply IAM.

### 1:35–2:35 — Completed transaction

Walk the timestamped completed case:

- `legacy-1` through the key.
- ProofV2 accepted once and replay rejected.
- Human-applied provider/binding and actual propagation duration.
- `wif-1` and H1–H8 at named controls.
- Human key-disable event and fresh `disabled: true` read.
- Fresh online legacy failure and post-disable `wif-2`.
- Forbidden service unchanged.

State that disabling does not revoke tokens minted earlier and that no universal external-consumer absence is claimed.

### 2:35–3:20 — Return to live proof

Show H4 reaching Google and failing at the provider condition. Show the authorized revision if complete. If pending, label it pending and rely only on the completed historical evidence.

### 3:20–3:50 — Receipt tamper proof

Verify the final receipt with the KMS public key, change one byte, and show failure. Open one GitHub run and one Cloud Run/audit source identifier.

Say: “KMS proves the receipt bytes and signer; external identifiers support the events.”

### 3:50–4:00 — Scoped close

> “At this receipt time, the named workflow deployed through WIF, eight tested hostile paths could not reach their protected targets, and a fresh authentication attempt with the disabled key failed.”

## Failure policy

- If a hostile path succeeds or reaches the wrong enforcement point, stop and mark `FAILED_SAFE`.
- If authorized live work remains pending, say pending; do not count it.
- Network failure means re-record; screenshots are not core proof.
- Previously recorded material must display its timestamp label.
- No splice may make historical evidence appear live.
- Claims such as “all access revoked,” “universally least privilege,” “enterprise ready,” “no other consumers,” or “KMS proves events” are prohibited.
