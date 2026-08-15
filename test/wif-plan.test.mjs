import assert from "node:assert/strict";
import test from "node:test";

import { buildWifPlan, verifyWifPlan } from "../src/wif-plan.mjs";

const input = {
  project_id: "keyless-k0-demo",
  project_number: "123456789",
  pool_id: "keyless-k0",
  provider_id: "github",
  owner_id: "111",
  repository_id: "222",
  owner: "trustphoneapp",
  repository: "keyless-cutover",
  service_account: "keyless-deploy@keyless-k0-demo.iam.gserviceaccount.com",
};

test("WIF compiler binds immutable GitHub identity and exact workflow context", () => {
  const plan = buildWifPlan(input);

  assert.equal(verifyWifPlan(input, plan), true);
  assert.equal(plan.audience, `https://iam.googleapis.com/${plan.provider}`);
  assert.match(plan.attribute_condition, /repository_owner_id=='111'/);
  assert.match(plan.attribute_condition, /repository_id=='222'/);
  assert.match(plan.attribute_condition, /workflow_ref=='trustphoneapp\/keyless-cutover\/.github\/workflows\/k0-deploy.yml@refs\/heads\/main'/);
  assert.match(plan.attribute_condition, /event_name=='push'/);
  assert.match(plan.attribute_condition, /environment=='production'/);
  assert.match(plan.attribute_condition, /runner_environment=='github-hosted'/);
  assert.equal(plan.impersonation_binding.role, "roles/iam.workloadIdentityUser");
  assert.match(plan.provider_config_hash, /^[a-f0-9]{64}$/);
  assert.match(plan.impersonation_binding_hash, /^[a-f0-9]{64}$/);
  assert.equal(plan.commands.flat().some((value) => /Owner|Editor|TokenCreator|\*/.test(value)), false);
  assert.equal(verifyWifPlan({ ...input, repository_id: "223" }, plan), false);
  assert.throws(() => buildWifPlan({ ...input, repository: "bad'repo" }), /invalid/);
});

test("WIF compiler refuses malformed, widening, or identity-ambiguous inputs", () => {
  const attacks = [
    ["empty project id", { ...input, project_id: "" }],
    ["uppercase project id", { ...input, project_id: "Keyless-K0-Demo" }],
    ["non-numeric owner id", { ...input, owner_id: "abc" }],
    ["non-numeric repository id", { ...input, repository_id: "2.2" }],
    ["owner path injection", { ...input, owner: "trust/phone" }],
    ["repository path injection", { ...input, repository: "../escape" }],
    ["broad service account", { ...input, service_account: "deploy@example.com" }],
    ["leading-zero owner id", { ...input, owner_id: "0111" }],
    ["control character owner", { ...input, owner: "trust\nphone" }],
    ["pool id too short", { ...input, pool_id: "ab" }],
    ["provider id with slash", { ...input, provider_id: "git/hub" }],
  ];
  for (const [label, value] of attacks) {
    assert.throws(() => buildWifPlan(value), /invalid/, label);
  }
  assert.throws(() => buildWifPlan({ ...input, extra: true }), /invalid/);
  assert.throws(() => buildWifPlan({ ...input, role: "roles/owner" }), /invalid/);

  const plan = buildWifPlan(input);
  assert.equal(verifyWifPlan({ ...input, owner_id: "112" }, plan), false);
  assert.equal(verifyWifPlan({ ...input, service_account: "other@keyless-k0-demo.iam.gserviceaccount.com" }, plan), false);
  assert.equal(verifyWifPlan({ ...input, pool_id: "other-pool" }, plan), false);
  assert.doesNotMatch(plan.attribute_condition, /event_name=='workflow_dispatch'/);
  assert.doesNotMatch(plan.attribute_condition, /\|\|/);
  assert.match(plan.impersonation_binding.member, /attribute\.repo_id\/222$/);
});
