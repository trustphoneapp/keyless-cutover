export function runRulesBaseline(testCase) {
  const text = testCase.bundle.evidence.map(({ text: value }) => value).join("\n");
  if (testCase.lane === "evidence") {
    if (/ignore (?:prior|the system)|say PASS/i.test(text)) return { pattern: "UNSUPPORTED" };
    if (/Two auth steps|matrix expression/i.test(text)) return { pattern: "AMBIGUOUS" };
    if (/google-github-actions\/auth/i.test(text)
        && /credentials_json/i.test(text)
        && /gcloud run deploy/i.test(text)) return { pattern: "CANDIDATE_DIRECT" };
    return { pattern: "AMBIGUOUS" };
  }
  const checks = [
    ["WORKFLOW_REF_MISMATCH", /workflow_ref|workflow.*(?:admits|expects).*(?:failed|reports)/i],
    ["REPOSITORY_ID_MISMATCH", /repository_id.*repository_id/is],
    ["ENVIRONMENT_CLAIM_MISSING", /environment.*(?:missing|omitted|no environment)/is],
    ["AUDIENCE_MISMATCH", /audience.*audience/is],
    ["ID_TOKEN_PERMISSION_MISSING", /id-token.*(?:missing|unavailable|cannot request)/is],
    ["IMPERSONATION_BINDING_MISSING", /service-account policy.*(?:no matching|different repository)/is],
    ["DOWNSTREAM_CLOUD_RUN_DENIED", /Cloud Run.*(?:rejected|permission denied)/is],
    ["PROPAGATION_PENDING", /(?:less than two minutes|48 seconds).*(?:denied|denial)/is],
  ];
  return { category: checks.find(([, pattern]) => pattern.test(text))?.[0] ?? "UNKNOWN" };
}
