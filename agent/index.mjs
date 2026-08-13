import { createKeylessAgentServer } from "./server.mjs";

let invokersPromise;

function loadInvokers() {
  invokersPromise ??= Promise.all([
    import("./invoke.mjs"),
    import("./taskmaster.mjs"),
  ]).then(([{ createAgentInvoker }, { evidenceAgent, recoveryAgent }]) => ({
    evidence: createAgentInvoker({ agent: evidenceAgent, lane: "evidence" }),
    recovery: createAgentInvoker({ agent: recoveryAgent, lane: "recovery" }),
  }));
  return invokersPromise;
}

const invoke = (lane) => async (bundle) => (await loadInvokers())[lane](bundle);

const server = createKeylessAgentServer({
  evidenceInvoker: invoke("evidence"),
  recoveryInvoker: invoke("recovery"),
  apiToken: process.env.KEYLESS_API_TOKEN,
});
const port = Number(process.env.PORT ?? 8080);
server.listen(port, "0.0.0.0", () => process.stdout.write(`keyless-agent listening on ${port}\n`));
