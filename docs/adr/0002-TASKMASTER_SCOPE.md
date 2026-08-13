# ADR 0002: Taskmaster scope and human IAM

- Status: Accepted
- Date: 2026-08-12
- Supersedes: Fleet positioning and autonomous-IAM portions of ADR 0001

## Context

Ten independent audits found that the single-workflow Keyless project does not satisfy the official Fortified Enterprise Fleet definition. They also found that a runtime allowed to call `setIamPolicy` cannot be technically restricted by IAM to one exact member, making the previous autonomous-mutation boundary too strong.

## Decision

- Enter The Taskmaster.
- Use one ADK Taskmaster on Cloud Run with Gemini 3.5 Flash through Vertex AI.
- Keep deterministic compilation and security oracles outside the model.
- Use Firestore only for challenge replay/state and KMS only after K0.
- Humans apply IAM, approve/merge the PR, and disable the key.
- Remove Cloud Tasks, Pub/Sub, Agent Engine, Fleet services, autonomous IAM, and the two-service control plane from the hackathon build.

## Consequences

The project is smaller, more truthful, and deliverable in approximately 56 focused hours. It gives up unattended IAM mutation and fleet positioning. Human gates are presented as separation of duties, while the agent still interprets evidence, diagnoses failures, opens a draft PR, coordinates verification, and assembles proof.
