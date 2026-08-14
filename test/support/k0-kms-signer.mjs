import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";

import { canonicalJson } from "../../src/evidence-artifact.mjs";

const K0_KMS_ALGORITHM = "RSA_SIGN_PKCS1_2048_SHA256";

export function createTestKmsSigner(keyVersion) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    trustAnchor: { key_version: keyVersion, algorithm: K0_KMS_ALGORITHM, public_key: publicKey },
    sidecar(receiptBytes, request) {
      const digest = createHash("sha256").update(receiptBytes).digest("base64");
      assert.equal(request.name, keyVersion);
      assert.equal(request.digest.sha256, digest);
      const signature = sign("sha256", receiptBytes, privateKey);
      assert.equal(verify("sha256", receiptBytes, publicKey, signature), true);
      return Buffer.from(canonicalJson({
        version: 1,
        name: keyVersion,
        algorithm: K0_KMS_ALGORITHM,
        digest_sha256: digest,
        signature: signature.toString("base64"),
      }));
    },
  };
}
